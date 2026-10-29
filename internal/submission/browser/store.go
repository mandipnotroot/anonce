// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package browser persists public bulletins and single-use round reviewer reads.
// It has no identity package or database dependency.
package browser

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mandipnotroot/anonce/internal/reviewprofile"
	"github.com/mandipnotroot/anonce/internal/submission/records"
)

var ErrDenied = errors.New("submission operation denied")

type Store struct {
	pool        *pgxpool.Pool
	records     *records.Store
	publication ed25519.PublicKey
}

func New(ctx context.Context, pool *pgxpool.Pool, publication ed25519.PublicKey) (*Store, error) {
	if len(publication) != 32 {
		return nil, ErrDenied
	}
	r, err := records.New(ctx, pool)
	if err != nil {
		return nil, ErrDenied
	}
	var ok bool
	if pool.QueryRow(ctx, `SELECT to_regclass('anonce.browser_bulletins') IS NOT NULL AND to_regclass('anonce.browser_review_challenges') IS NOT NULL`).Scan(&ok) != nil || !ok {
		return nil, ErrDenied
	}
	return &Store{pool, r, bytes.Clone(publication)}, nil
}

func (s *Store) Publish(ctx context.Context, raw []byte) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	b, err := reviewprofile.ParseBulletin(raw, s.publication)
	if err != nil {
		return ErrDenied
	}
	digest := sha256.Sum256(raw)
	err = s.records.CreateRound(ctx, records.Round{ID: records.ID(b.ID), BulletinDigest: digest, OpensAt: b.Opens, ClosesAt: b.Closes})
	if err != nil && !errors.Is(err, records.ErrConflict) {
		return ErrDenied
	}
	// Recover a process failure between metadata provisioning and public insertion,
	// but only for the exact immutable, already verified common bulletin.
	tag, err := s.pool.Exec(ctx, `INSERT INTO anonce.browser_bulletins(round_id,bulletin) SELECT id,$2 FROM anonce.submission_rounds WHERE id=$1 AND bulletin_digest=$3 AND opens_at=$4 AND closes_at=$5 ON CONFLICT(round_id) DO NOTHING`, b.ID[:], raw, digest[:], b.Opens, b.Closes)
	if err != nil {
		return ErrDenied
	}
	if tag.RowsAffected() == 0 {
		var stored []byte
		if s.pool.QueryRow(ctx, `SELECT bulletin FROM anonce.browser_bulletins WHERE round_id=$1`, b.ID[:]).Scan(&stored) != nil || !bytes.Equal(stored, raw) {
			return ErrDenied
		}
	}
	return nil
}

func (s *Store) Bulletin(ctx context.Context, id []byte) (reviewprofile.Bulletin, []byte, error) {
	if err := s.ready(ctx); err != nil {
		return reviewprofile.Bulletin{}, nil, err
	}
	if len(id) != 16 {
		return reviewprofile.Bulletin{}, nil, ErrDenied
	}
	var raw []byte
	if s.pool.QueryRow(ctx, `SELECT bulletin FROM anonce.browser_bulletins WHERE round_id=$1`, id).Scan(&raw) != nil {
		return reviewprofile.Bulletin{}, nil, ErrDenied
	}
	b, err := reviewprofile.ParseBulletin(raw, s.publication)
	if err != nil {
		return reviewprofile.Bulletin{}, nil, ErrDenied
	}
	return b, raw, nil
}

func (s *Store) Accept(ctx context.Context, id, token, envelope []byte, receiptKey ed25519.PrivateKey) ([]byte, error) {
	b, raw, err := s.Bulletin(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(envelope) != reviewprofile.EnvelopeSize || envelope[0] != 1 {
		return nil, ErrDenied
	}
	spend, err := reviewprofile.VerifyToken(b, raw, token)
	if err != nil {
		return nil, ErrDenied
	}
	digest := sha256.Sum256(raw)
	ref, err := s.records.Accept(ctx, records.ID(b.ID), digest[:], spend[:], envelope)
	if err != nil {
		return nil, ErrDenied
	}
	return reviewprofile.Receipt(b, raw, [16]byte(ref.ID), spend, envelope, receiptKey)
}

func (s *Store) Challenge(ctx context.Context, id, cursor, secret []byte) ([]byte, error) {
	b, raw, err := s.Bulletin(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(cursor) != 16 || len(secret) != 32 {
		return nil, ErrDenied
	}
	envelope, err := reviewprofile.SealReviewChallenge(b, raw, secret)
	if err != nil {
		return nil, ErrDenied
	}
	digest := sha256.Sum256(secret)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, ErrDenied
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var locked []byte
	if tx.QueryRow(ctx, `SELECT id FROM anonce.submission_rounds WHERE id=$1 FOR UPDATE`, id).Scan(&locked) != nil {
		return nil, ErrDenied
	}
	if _, err = tx.Exec(ctx, `DELETE FROM anonce.browser_review_challenges WHERE round_id=$1 AND expires_at<=statement_timestamp()`, id); err != nil {
		return nil, ErrDenied
	}
	var count int
	if tx.QueryRow(ctx, `SELECT count(*) FROM anonce.browser_review_challenges WHERE round_id=$1`, id).Scan(&count) != nil || count >= 16 {
		return nil, ErrDenied
	}
	tag, err := tx.Exec(ctx, `INSERT INTO anonce.browser_review_challenges(digest,round_id,cursor) SELECT $1,$2,$3 WHERE statement_timestamp()<$4`, digest[:], id, cursor, b.ReviewUntil)
	if err != nil || tag.RowsAffected() != 1 || tx.Commit(ctx) != nil {
		return nil, ErrDenied
	}
	return envelope, nil
}

type Ciphertext struct {
	ID       []byte `json:"id"`
	Envelope []byte `json:"envelope"`
}

func (s *Store) Read(ctx context.Context, id, secret []byte) ([]Ciphertext, []byte, error) {
	b, _, err := s.Bulletin(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if len(secret) != 32 {
		return nil, nil, ErrDenied
	}
	digest := sha256.Sum256(secret)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, ErrDenied
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var cursor []byte
	if tx.QueryRow(ctx, `DELETE FROM anonce.browser_review_challenges WHERE digest=$1 AND round_id=$2 AND expires_at>statement_timestamp() AND statement_timestamp()<$3 RETURNING cursor`, digest[:], id, b.ReviewUntil).Scan(&cursor) != nil {
		return nil, nil, ErrDenied
	}
	rows, err := tx.Query(ctx, `SELECT id,ciphertext FROM anonce.submission_records WHERE round_id=$1 AND id>$2 ORDER BY id LIMIT 50`, id, cursor)
	if err != nil {
		return nil, nil, ErrDenied
	}
	var out []Ciphertext
	for rows.Next() {
		var c Ciphertext
		if rows.Scan(&c.ID, &c.Envelope) != nil {
			rows.Close()
			return nil, nil, ErrDenied
		}
		out = append(out, c)
		cursor = bytes.Clone(c.ID)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || tx.Commit(ctx) != nil {
		return nil, nil, ErrDenied
	}
	return out, cursor, nil
}

func (s *Store) ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrDenied, err)
	}
	if s == nil || s.pool == nil || s.records == nil || len(s.publication) != ed25519.PublicKeySize {
		return ErrDenied
	}
	return nil
}

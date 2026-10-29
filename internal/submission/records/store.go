// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package records atomically persists caller-verified anonymous submissions. It
// does not verify tokens, bulletins, or encryption and must not be exposed directly
// to untrusted requests. See docs/database.md for the internal storage contract.
package records

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// MaxCiphertextSize is a storage bound, not an admitted envelope wire profile.
	MaxCiphertextSize = 65536
	operationTimeout  = 5 * time.Second
)

var (
	ErrInvalidInput = errors.New("invalid submission storage input")
	ErrUnavailable  = errors.New("submission storage or round unavailable")
	ErrConflict     = errors.New("submission storage conflict")
)

// ID is an opaque round or storage reference, never an account or membership ID.
type ID [16]byte

// Round contains immutable admission metadata from an independently verified
// common bulletin. Provisioning and cancellation require caller authorization.
type Round struct {
	ID             ID
	BulletinDigest [32]byte
	OpensAt        time.Time
	ClosesAt       time.Time
}

// Reference identifies durable storage only. It is not a signed receipt, proof of
// inclusion, reviewer authorization, or a public wire format.
type Reference struct {
	ID         ID
	AcceptedAt time.Time
}

// Store borrows a submission runtime pool without query/parameter logging. Callers
// must preserve its checked database and role on all connections. It is safe for
// concurrent use; the zero value fails closed. No identity-side pool is admitted.
type Store struct{ pool *pgxpool.Pool }

func New(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var valid bool
	err := pool.QueryRow(ctx, `SELECT current_database() = 'submission'
        AND current_user = 'anonce_runtime' AND session_user = 'anonce_runtime'
        AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
        AND NOT pg_has_role(current_user, 'anonce_owner', 'MEMBER')
        AND to_regclass('anonce.submission_rounds') IS NOT NULL
        AND to_regclass('anonce.submission_records') IS NOT NULL
        AND (SELECT count(*) = 1 AND bool_and(singleton AND service = 'submission')
             FROM anonce.storage_boundary)
        FROM pg_roles WHERE rolname = current_user`).Scan(&valid)
	if err != nil || !valid {
		return nil, failure(ctx, "check submission storage boundary")
	}
	return &Store{pool: pool}, nil
}

// CreateRound provisions an immutable round after caller verification of its
// bulletin and publication authority. Existing IDs conflict, even for identical
// input. No schedule or bulletin replacement, reopening, or un-cancellation exists.
func (s *Store) CreateRound(ctx context.Context, round Round) error {
	if !validRound(round) {
		return ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return failure(ctx, "begin round creation")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `INSERT INTO anonce.submission_rounds(id, bulletin_digest, opens_at, closes_at)
        VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING`,
		round.ID[:], round.BulletinDigest[:], round.OpensAt, round.ClosesAt)
	if err != nil {
		return failure(ctx, "create submission round")
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return failure(ctx, "commit round creation")
	}
	return nil
}

// CancelRound prevents subsequent admission without modifying stored records.
// It requires caller authorization. It serializes with acceptance, is idempotent
// for known rounds, and returns ErrUnavailable for unknown rounds.
func (s *Store) CancelRound(ctx context.Context, id ID) error {
	if id == (ID{}) {
		return ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return failure(ctx, "begin round cancellation")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Keep a queued UPDATE uncommitted if its context is cancelled while waiting
	// on acceptance. Autocommit could otherwise finish after the caller returned.
	tag, err := tx.Exec(ctx, "UPDATE anonce.submission_rounds SET cancelled = true WHERE id = $1", id[:])
	if err != nil {
		return failure(ctx, "cancel submission round")
	}
	if tag.RowsAffected() != 1 {
		return ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return failure(ctx, "commit round cancellation")
	}
	return nil
}

// Accept atomically stores one ciphertext per round-scoped canonical spend
// digest. The trusted caller MUST first verify the token, derive its digest from
// canonical token input rather than signature bytes, and validate the encrypted
// envelope and common bulletin. A digest is not itself authorization.
//
// Only an identical ciphertext retry during the open window returns the original
// reference. A different payload conflicts without replacing anything. Unknown,
// cancelled, unopened, closed, or differently bound rounds return ErrUnavailable.
// Inputs remain caller-owned and must not change until return. No reference is
// returned on error; after uncertain commit, retry only the exact original input.
func (s *Store) Accept(ctx context.Context, round ID, bulletin, spend, ciphertext []byte) (Reference, error) {
	if !validSubmission(round, bulletin, spend, ciphertext) {
		return Reference{}, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		return Reference{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Reference{}, failure(ctx, "begin submission acceptance")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Shared row locks permit concurrent acceptance while ordering cancellation.
	// Check the window in the INSERT, not with transaction-start time or before
	// a potentially blocking round lock.
	var locked []byte
	err = tx.QueryRow(ctx, "SELECT id FROM anonce.submission_rounds WHERE id = $1 FOR SHARE", round[:]).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return Reference{}, ErrUnavailable
	}
	if err != nil {
		return Reference{}, failure(ctx, "lock submission round")
	}
	var candidate ID
	rand.Read(candidate[:])
	var id []byte
	var reference Reference
	err = tx.QueryRow(ctx, `INSERT INTO anonce.submission_records(id, round_id, spend_digest, ciphertext)
        SELECT $1, id, $3, $4 FROM anonce.submission_rounds
        WHERE id = $2 AND bulletin_digest = $5 AND NOT cancelled
          AND opens_at <= statement_timestamp() AND closes_at > statement_timestamp()
        ON CONFLICT (round_id, spend_digest) DO NOTHING RETURNING id, accepted_at`,
		candidate[:], round[:], spend, ciphertext, bulletin).Scan(&id, &reference.AcceptedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// DO NOTHING can wait for an insertion invisible to its initial snapshot.
		// A separate Read Committed statement observes that committed winner. Never
		// update ciphertext or use a no-op UPDATE merely to return a reference.
		var same bool
		err = tx.QueryRow(ctx, `SELECT r.id, r.accepted_at, r.ciphertext = $3
            FROM anonce.submission_records r JOIN anonce.submission_rounds b ON b.id = r.round_id
            WHERE r.round_id = $1 AND r.spend_digest = $2 AND b.bulletin_digest = $4
              AND NOT b.cancelled AND b.opens_at <= statement_timestamp()
              AND b.closes_at > statement_timestamp()`, round[:], spend, ciphertext, bulletin).Scan(&id, &reference.AcceptedAt, &same)
		if errors.Is(err, pgx.ErrNoRows) {
			return Reference{}, ErrUnavailable
		}
		if err == nil && !same {
			return Reference{}, ErrConflict
		}
	}
	if err != nil || len(id) != len(reference.ID) || reference.AcceptedAt.IsZero() {
		return Reference{}, failure(ctx, "persist submission record")
	}
	copy(reference.ID[:], id)
	if err := tx.Commit(ctx); err != nil {
		return Reference{}, failure(ctx, "commit submission acceptance")
	}
	return reference, nil
}

func validRound(round Round) bool {
	return round.ID != (ID{}) && validTime(round.OpensAt) && validTime(round.ClosesAt) && round.ClosesAt.After(round.OpensAt)
}

func validTime(value time.Time) bool {
	year := value.UTC().Year()
	return !value.IsZero() && year >= 1 && year <= 9999 && value.Nanosecond()%1000 == 0
}

func validSubmission(round ID, bulletin, spend, ciphertext []byte) bool {
	return round != (ID{}) && len(bulletin) == 32 && len(spend) == 32 && len(ciphertext) >= 1 && len(ciphertext) <= MaxCiphertextSize
}

func (s *Store) ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.pool == nil {
		return ErrUnavailable
	}
	return nil
}

// SQL diagnostics can contain ciphertext, bearer-related data, or credentials.
// Preserve only operation context and cancellation, never driver error text.
func failure(ctx context.Context, operation string) error {
	return errors.Join(errors.New(operation), ctx.Err())
}

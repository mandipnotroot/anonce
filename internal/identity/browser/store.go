// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package browser persists the opt-in identity browser workflow. Its database is
// never connected to anonymous submission storage.
package browser

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mandipnotroot/anonce/internal/client/membercsr"
	"github.com/mandipnotroot/anonce/internal/identity/accounts"
	"github.com/mandipnotroot/anonce/internal/reviewprofile"
)

var (
	ErrDenied       = errors.New("identity operation denied")
	usernamePattern = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)
)

func ValidUsername(s string) bool { return usernamePattern.MatchString(s) }

type (
	Store struct{ pool *pgxpool.Pool }
	User  struct {
		ID         accounts.ID         `json:"id"`
		Name       string              `json:"name"`
		Credential webauthn.Credential `json:"credential"`
		Admin      bool                `json:"admin"`
	}
)

func (u User) WebAuthnID() []byte          { return u.ID[:] }
func (u User) WebAuthnName() string        { return u.Name }
func (u User) WebAuthnDisplayName() string { return u.Name }
func (u User) WebAuthnCredentials() []webauthn.Credential {
	if len(u.Credential.ID) == 0 {
		return nil
	}
	return []webauthn.Credential{u.Credential}
}

func New(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	if _, err := accounts.New(ctx, pool); err != nil {
		return nil, ErrDenied
	}
	var ok bool
	if pool.QueryRow(ctx, `SELECT to_regclass('anonce.browser_credentials') IS NOT NULL AND to_regclass('anonce.browser_issuances') IS NOT NULL`).Scan(&ok) != nil || !ok {
		return nil, ErrDenied
	}
	return &Store{pool}, nil
}

func scanUser(row pgx.Row) (User, error) {
	var u User
	var id, data []byte
	if row.Scan(&id, &u.Name, &data, &u.Admin) != nil || len(id) != 16 || json.Unmarshal(data, &u.Credential) != nil {
		return User{}, ErrDenied
	}
	copy(u.ID[:], id)
	return u, nil
}

func (s *Store) User(ctx context.Context, name string) (User, error) {
	if err := s.ready(ctx); err != nil {
		return User{}, err
	}
	if !ValidUsername(name) {
		return User{}, ErrDenied
	}
	return scanUser(s.pool.QueryRow(ctx, `SELECT c.account_id,c.username,c.credential,c.administrator FROM anonce.browser_credentials c JOIN anonce.accounts a ON a.id=c.account_id WHERE c.username=$1 AND a.state='active'`, name))
}

func (s *Store) Register(ctx context.Context, u User) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if !ValidUsername(u.Name) || u.ID == (accounts.ID{}) || len(u.Credential.ID) < 1 || len(u.Credential.ID) > 1024 {
		return ErrDenied
	}
	data, err := json.Marshal(u.Credential)
	if err != nil || len(data) > 32768 {
		return ErrDenied
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ErrDenied
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `INSERT INTO anonce.accounts(id) VALUES($1)`, u.ID[:]); err != nil {
		return ErrDenied
	}
	if _, err = tx.Exec(ctx, `INSERT INTO anonce.browser_credentials(account_id,username,credential_id,credential,administrator) VALUES($1,$2,$3,$4,$5)`, u.ID[:], u.Name, u.Credential.ID, data, u.Admin); err != nil {
		return ErrDenied
	}
	if tx.Commit(ctx) != nil {
		return ErrDenied
	}
	return nil
}

// Login serializes verifier/counter updates with other assertions and disabling.
// The callback must independently verify the complete WebAuthn assertion.
func (s *Store) Login(ctx context.Context, name string, verify func(User) (*webauthn.Credential, error)) (User, error) {
	if err := s.ready(ctx); err != nil {
		return User{}, err
	}
	if !ValidUsername(name) || verify == nil {
		return User{}, ErrDenied
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return User{}, ErrDenied
	}
	defer func() { _ = tx.Rollback(ctx) }()
	u, err := scanUser(tx.QueryRow(ctx, `SELECT c.account_id,c.username,c.credential,c.administrator FROM anonce.browser_credentials c JOIN anonce.accounts a ON a.id=c.account_id WHERE c.username=$1 AND a.state='active' FOR UPDATE OF a,c`, name))
	if err != nil {
		return User{}, ErrDenied
	}
	credential, err := verify(u)
	if err != nil || credential == nil || credential.Authenticator.CloneWarning {
		return User{}, ErrDenied
	}
	data, err := json.Marshal(credential)
	if err != nil {
		return User{}, ErrDenied
	}
	if _, err = tx.Exec(ctx, `UPDATE anonce.browser_credentials SET credential=$2 WHERE account_id=$1`, u.ID[:], data); err != nil || tx.Commit(ctx) != nil {
		return User{}, ErrDenied
	}
	u.Credential = *credential
	return u, nil
}

func (s *Store) SaveCeremony(ctx context.Context, secret []byte, kind string, data []byte) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if len(secret) != 32 || len(data) > 16384 {
		return ErrDenied
	}
	digest := sha256.Sum256(secret)
	// Fixed aggregate bound, serialized across processes. Restart cannot reset it.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ErrDenied
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `LOCK TABLE anonce.browser_ceremonies IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return ErrDenied
	}
	if _, err = tx.Exec(ctx, `DELETE FROM anonce.browser_ceremonies WHERE expires_at <= statement_timestamp()`); err != nil {
		return ErrDenied
	}
	var count int
	if tx.QueryRow(ctx, `SELECT count(*) FROM anonce.browser_ceremonies`).Scan(&count) != nil || count >= 256 {
		return ErrDenied
	}
	if _, err = tx.Exec(ctx, `INSERT INTO anonce.browser_ceremonies(digest,kind,data) VALUES($1,$2,$3)`, digest[:], kind, data); err != nil || tx.Commit(ctx) != nil {
		return ErrDenied
	}
	return nil
}

func (s *Store) TakeCeremony(ctx context.Context, secret []byte, kind string) ([]byte, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if len(secret) != 32 {
		return nil, ErrDenied
	}
	digest := sha256.Sum256(secret)
	var data []byte
	if s.pool.QueryRow(ctx, `DELETE FROM anonce.browser_ceremonies WHERE digest=$1 AND kind=$2 AND expires_at>statement_timestamp() RETURNING data`, digest[:], kind).Scan(&data) != nil {
		return nil, ErrDenied
	}
	return data, nil
}

// withSession keeps admission ordered with account/session revocation and backup
// mutations. It does not accept a request-supplied account identifier.
func (s *Store) withSession(ctx context.Context, token []byte, recent, admin bool, fn func(pgx.Tx, accounts.ID) error) (result error) {
	if err := s.ready(ctx); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	defer func() {
		if result != nil {
			result = errors.Join(result, ctx.Err())
		}
	}()
	if len(token) != 32 {
		return ErrDenied
	}
	digest := sha256.Sum256(token)
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ErrDenied
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var id []byte
	if tx.QueryRow(ctx, `SELECT account_id FROM anonce.account_sessions WHERE token_digest=$1`, digest[:]).Scan(&id) != nil || len(id) != 16 {
		return ErrDenied
	}
	var state string
	if tx.QueryRow(ctx, `SELECT state FROM anonce.accounts WHERE id=$1 FOR UPDATE`, id).Scan(&state) != nil || state != "active" {
		return ErrDenied
	}
	var fresh, isAdmin bool
	if tx.QueryRow(ctx, `SELECT s.created_at>statement_timestamp()-interval '5 minutes',c.administrator FROM anonce.account_sessions s JOIN anonce.browser_credentials c ON c.account_id=s.account_id WHERE s.token_digest=$1 AND s.created_at<=statement_timestamp() AND s.expires_at>statement_timestamp()`, digest[:]).Scan(&fresh, &isAdmin) != nil || recent && !fresh || admin && !isAdmin {
		return ErrDenied
	}
	var owner accounts.ID
	copy(owner[:], id)
	if fn(tx, owner) != nil || tx.Commit(ctx) != nil {
		return ErrDenied
	}
	return nil
}

func (s *Store) Current(ctx context.Context, token []byte) (User, error) {
	var u User
	err := s.withSession(ctx, token, false, false, func(tx pgx.Tx, id accounts.ID) error {
		var err error
		u, err = scanUser(tx.QueryRow(ctx, `SELECT account_id,username,credential,administrator FROM anonce.browser_credentials WHERE account_id=$1`, id[:]))
		return err
	})
	if err != nil {
		return User{}, err
	}
	return u, nil
}

func (s *Store) Invite(ctx context.Context, token []byte) ([]byte, error) {
	code := make([]byte, 32)
	rand.Read(code)
	digest := sha256.Sum256(code)
	id := make([]byte, 16)
	rand.Read(id)
	err := s.withSession(ctx, token, true, true, func(tx pgx.Tx, _ accounts.ID) error {
		_, err := tx.Exec(ctx, `INSERT INTO anonce.browser_memberships(id,code_digest,expires_at) VALUES($1,$2,statement_timestamp()+interval '24 hours')`, id, digest[:])
		return err
	})
	if err != nil {
		clear(code)
		return nil, err
	}
	return code, nil
}

func (s *Store) Enroll(ctx context.Context, token, code, csr []byte, ca *x509.Certificate, key ed25519.PrivateKey) ([]byte, error) {
	public, err := membercsr.Parse(csr)
	if err != nil || len(code) != 32 || !validAuthority(ca) || !ca.NotAfter.After(time.Now().Add(365*24*time.Hour)) {
		return nil, ErrDenied
	}
	digest := sha256.Sum256(code)
	var certificate []byte
	err = s.withSession(ctx, token, true, false, func(tx pgx.Tx, owner accounts.ID) error {
		var expected []byte
		if tx.QueryRow(ctx, `SELECT public_key FROM anonce.member_key_backups WHERE account_id=$1 AND backup IS NOT NULL`, owner[:]).Scan(&expected) != nil || !bytes.Equal(expected, public) {
			return ErrDenied
		}
		var member []byte
		if tx.QueryRow(ctx, `SELECT id FROM anonce.browser_memberships WHERE code_digest=$1 AND account_id IS NULL AND NOT revoked AND expires_at>statement_timestamp() FOR UPDATE`, digest[:]).Scan(&member) != nil {
			return ErrDenied
		}
		serial := make([]byte, 16)
		rand.Read(serial)
		serial[0] |= 1
		now := time.Now().UTC().Truncate(time.Second)
		leaf := &x509.Certificate{SerialNumber: new(big.Int).SetBytes(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
		certificate, err = x509.CreateCertificate(rand.Reader, leaf, ca, ed25519.PublicKey(public), key)
		if err != nil {
			return ErrDenied
		}
		_, err = tx.Exec(ctx, `UPDATE anonce.browser_memberships SET account_id=$2,public_key=$3,certificate=$4 WHERE id=$1`, member, owner[:], public, certificate)
		return err
	})
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

type Round struct {
	ID            []byte    `json:"id"`
	Question      string    `json:"question"`
	ReviewerName  string    `json:"reviewer"`
	Opens         time.Time `json:"opens"`
	Closes        time.Time `json:"closes"`
	ReviewUntil   time.Time `json:"review_until"`
	ResponseLimit int       `json:"response_limit"`
	ReviewerKey   []byte    `json:"reviewer_key"`
	Bulletin      []byte    `json:"bulletin"`
	Assigned      bool      `json:"assigned"`
}

func (s *Store) CreateRound(ctx context.Context, token []byte, r Round) ([]byte, error) {
	if len(r.Question) < 1 || len(r.Question) > 1024 || !utf8.ValidString(r.Question) || !ValidUsername(r.ReviewerName) || r.ResponseLimit != 1 || r.Opens.Nanosecond() != 0 || r.Closes.Nanosecond() != 0 || r.ReviewUntil.Nanosecond() != 0 || r.Opens.Unix() < 1767225600 || r.ReviewUntil.Unix() >= 4133980800 || !r.Closes.After(r.Opens) || !r.ReviewUntil.After(r.Closes) || r.ReviewUntil.Sub(r.Closes) > 30*24*time.Hour {
		return nil, ErrDenied
	}
	id := make([]byte, 16)
	rand.Read(id)
	err := s.withSession(ctx, token, true, true, func(tx pgx.Tx, _ accounts.ID) error {
		tag, err := tx.Exec(ctx, `INSERT INTO anonce.browser_rounds(id,question,reviewer_account,opens_at,closes_at,review_until,response_limit) SELECT $1,$2,c.account_id,$4,$5,$6,$7 FROM anonce.browser_credentials c JOIN anonce.accounts a ON a.id=c.account_id WHERE c.username=$3 AND a.state='active'`, id, r.Question, r.ReviewerName, r.Opens, r.Closes, r.ReviewUntil, r.ResponseLimit)
		if err != nil || tag.RowsAffected() != 1 {
			return ErrDenied
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return id, nil
}

func (s *Store) Rounds(ctx context.Context, token []byte) ([]Round, error) {
	var out []Round
	err := s.withSession(ctx, token, false, false, func(tx pgx.Tx, owner accounts.ID) error {
		rows, err := tx.Query(ctx, `SELECT r.id,r.question,c.username,r.opens_at,r.closes_at,r.review_until,r.response_limit,r.reviewer_key,r.bulletin,r.reviewer_account=$1 FROM anonce.browser_rounds r JOIN anonce.browser_credentials c ON c.account_id=r.reviewer_account WHERE r.bulletin IS NOT NULL OR r.reviewer_account=$1 OR EXISTS(SELECT 1 FROM anonce.browser_credentials WHERE account_id=$1 AND administrator) ORDER BY r.opens_at,r.id LIMIT 100`, owner[:])
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r Round
			if rows.Scan(&r.ID, &r.Question, &r.ReviewerName, &r.Opens, &r.Closes, &r.ReviewUntil, &r.ResponseLimit, &r.ReviewerKey, &r.Bulletin, &r.Assigned) != nil {
				return ErrDenied
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) PrepareReviewer(ctx context.Context, token, id, public []byte) error {
	if len(id) != 16 || len(public) != 32 {
		return ErrDenied
	}
	return s.withSession(ctx, token, true, false, func(tx pgx.Tx, owner accounts.ID) error {
		tag, err := tx.Exec(ctx, `UPDATE anonce.browser_rounds SET reviewer_key=$3 WHERE id=$1 AND reviewer_account=$2 AND bulletin IS NULL AND (reviewer_key IS NULL OR reviewer_key=$3)`, id, owner[:], public)
		if err != nil || tag.RowsAffected() != 1 {
			return ErrDenied
		}
		return nil
	})
}

func (s *Store) Publish(ctx context.Context, token, id []byte, limit int, signing ed25519.PrivateKey, receipt ed25519.PublicKey) ([]byte, error) {
	if len(id) != 16 || limit != 1 {
		return nil, ErrDenied
	}
	if err := s.withSession(ctx, token, true, true, func(tx pgx.Tx, _ accounts.ID) error {
		var ready bool
		if tx.QueryRow(ctx, `SELECT bulletin IS NULL AND reviewer_key IS NOT NULL FROM anonce.browser_rounds WHERE id=$1`, id).Scan(&ready) != nil || !ready {
			return ErrDenied
		}
		return nil
	}); err != nil {
		return nil, err
	}
	// Generate outside the account lock. Publication rechecks all authority/state.
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, ErrDenied
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	defer clear(der)
	var raw []byte
	err = s.withSession(ctx, token, true, true, func(tx pgx.Tx, _ accounts.ID) error {
		var b reviewprofile.Bulletin
		copy(b.ID[:], id)
		b.ResponseLimit = 1
		b.RSA = &key.PublicKey
		b.ReceiptKey = receipt
		if tx.QueryRow(ctx, `SELECT question,reviewer_key,opens_at,closes_at,review_until FROM anonce.browser_rounds WHERE id=$1 AND bulletin IS NULL AND reviewer_key IS NOT NULL FOR UPDATE`, id).Scan(&b.Question, &b.Reviewer, &b.Opens, &b.Closes, &b.ReviewUntil) != nil {
			return ErrDenied
		}
		raw, err = reviewprofile.SignBulletin(b, signing)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE anonce.browser_rounds SET rsa_private=$2,bulletin=$3 WHERE id=$1`, id, der, raw)
		return err
	})
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (s *Store) Challenge(ctx context.Context, token, id, blinded []byte) ([]byte, error) {
	if len(id) != 16 || len(blinded) != 384 {
		return nil, ErrDenied
	}
	var challenge []byte
	sessionDigest := sha256.Sum256(token)
	err := s.withSession(ctx, token, false, false, func(tx pgx.Tx, owner accounts.ID) error {
		var member, raw []byte
		if tx.QueryRow(ctx, `SELECT id FROM anonce.browser_memberships WHERE account_id=$1 AND NOT revoked`, owner[:]).Scan(&member) != nil {
			return ErrDenied
		}
		if tx.QueryRow(ctx, `SELECT bulletin FROM anonce.browser_rounds WHERE id=$1 AND bulletin IS NOT NULL AND opens_at<=statement_timestamp() AND closes_at>statement_timestamp()`, id).Scan(&raw) != nil {
			return ErrDenied
		}
		if _, err := tx.Exec(ctx, `DELETE FROM anonce.browser_issue_challenges WHERE membership_id=$1 AND expires_at<=statement_timestamp()`, member); err != nil {
			return err
		}
		nonce := make([]byte, 32)
		rand.Read(nonce)
		digest := sha256.Sum256(raw)
		blindDigest := sha256.Sum256(blinded)
		challenge = append([]byte{1}, id...)
		challenge = append(challenge, digest[:]...)
		challenge = append(challenge, nonce...)
		challenge = append(challenge, blindDigest[:]...)
		tag, err := tx.Exec(ctx, `INSERT INTO anonce.browser_issue_challenges(nonce,session_digest,membership_id,round_id,challenge) SELECT $1,$2,$3,$4,$5 WHERE NOT EXISTS(SELECT 1 FROM anonce.browser_issuances WHERE membership_id=$3 AND round_id=$4)`, nonce, sessionDigest[:], member, id, challenge)
		if err != nil || tag.RowsAffected() != 1 {
			return ErrDenied
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return challenge, nil
}

func (s *Store) Issue(ctx context.Context, token, challenge, signature, blinded []byte, ca *x509.Certificate) ([]byte, error) {
	message, err := reviewprofile.IssuanceMessage(challenge)
	if err != nil || len(signature) != 64 || len(blinded) != 384 {
		return nil, ErrDenied
	}
	blindDigest := sha256.Sum256(blinded)
	if !bytes.Equal(blindDigest[:], challenge[81:113]) {
		return nil, ErrDenied
	}
	sessionDigest := sha256.Sum256(token)
	var der []byte
	err = s.withSession(ctx, token, false, false, func(tx pgx.Tx, owner accounts.ID) error {
		var member, public, cert, stored, raw []byte
		if tx.QueryRow(ctx, `DELETE FROM anonce.browser_issue_challenges WHERE nonce=$1 AND session_digest=$2 AND expires_at>statement_timestamp() RETURNING membership_id,challenge`, challenge[49:81], sessionDigest[:]).Scan(&member, &stored) != nil || !bytes.Equal(stored, challenge) {
			return ErrDenied
		}
		if tx.QueryRow(ctx, `SELECT public_key,certificate FROM anonce.browser_memberships WHERE id=$1 AND account_id=$2 AND NOT revoked FOR UPDATE`, member, owner[:]).Scan(&public, &cert) != nil || !ed25519.Verify(ed25519.PublicKey(public), message, signature) {
			return ErrDenied
		}
		leaf, err := x509.ParseCertificate(cert)
		if err != nil || !validAuthority(ca) || leaf.CheckSignatureFrom(ca) != nil || leaf.IsCA || leaf.SignatureAlgorithm != x509.PureEd25519 || leaf.KeyUsage != x509.KeyUsageDigitalSignature || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
			return ErrDenied
		}
		pub, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok || !bytes.Equal(pub, public) {
			return ErrDenied
		}
		if tx.QueryRow(ctx, `SELECT rsa_private,bulletin FROM anonce.browser_rounds WHERE id=$1 AND opens_at<=statement_timestamp() AND closes_at>statement_timestamp()`, challenge[1:17]).Scan(&der, &raw) != nil {
			return ErrDenied
		}
		digest := sha256.Sum256(raw)
		if !bytes.Equal(digest[:], challenge[17:49]) {
			return ErrDenied
		}
		_, err = tx.Exec(ctx, `INSERT INTO anonce.browser_issuances(membership_id,round_id) VALUES($1,$2)`, member, challenge[1:17])
		return err
	})
	if err != nil {
		clear(der)
		return nil, err
	}
	defer clear(der)
	// Reservation commits before the signing oracle is invoked. Never retry/refund.
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil || key.N.BitLen() != 3072 {
		return nil, ErrDenied
	}
	representative := new(big.Int).SetBytes(blinded)
	if representative.Sign() <= 0 || representative.Cmp(key.N) >= 0 {
		return nil, ErrDenied
	}
	sig, err := blindrsa.NewSigner(key).BlindSign(blinded)
	if err != nil || ctx.Err() != nil {
		clear(sig)
		return nil, errors.Join(ErrDenied, ctx.Err())
	}
	return sig, nil
}

func validAuthority(ca *x509.Certificate) bool {
	if ca == nil || !ca.IsCA || ca.SignatureAlgorithm != x509.PureEd25519 || ca.KeyUsage&x509.KeyUsageCertSign == 0 || time.Now().Before(ca.NotBefore) || !time.Now().Before(ca.NotAfter) {
		return false
	}
	_, ok := ca.PublicKey.(ed25519.PublicKey)
	return ok && ca.CheckSignatureFrom(ca) == nil
}

func (s *Store) ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrDenied, err)
	}
	if s == nil || s.pool == nil {
		return ErrDenied
	}
	return nil
}

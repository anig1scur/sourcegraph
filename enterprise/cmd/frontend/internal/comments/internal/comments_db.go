package internal

import (
	"context"
	"database/sql"
	"time"

	"github.com/keegancsmith/sqlf"
	"github.com/pkg/errors"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/db"
	"github.com/sourcegraph/sourcegraph/enterprise/cmd/frontend/internal/comments/types"
	"github.com/sourcegraph/sourcegraph/pkg/db/dbconn"
)

// DBComment describes a comment.
type DBComment struct {
	ID           int64
	Object       types.CommentObject
	AuthorUserID int32
	Body         string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// ErrCommentNotFound occurs when a database operation expects a specific comment to exist but it
// does not exist.
var ErrCommentNotFound = errors.New("comment not found")

type DBComments struct{}

const selectColumns = `id, author_user_id, body, created_at, updated_at, thread_id, campaign_id`

// Create creates a comment. The comment argument's (Comment).ID field is ignored. The new comment
// is returned.
func (DBComments) Create(ctx context.Context, tx *sql.Tx, comment *DBComment) (*DBComment, error) {
	if Mocks.Comments.Create != nil {
		return Mocks.Comments.Create(comment)
	}

	var dbh interface {
		QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	}
	if tx != nil {
		dbh = tx
	} else {
		dbh = dbconn.Global
	}
	return DBComments{}.scanRow(dbh.QueryRowContext(ctx,
		`INSERT INTO comments(`+selectColumns+`) VALUES(DEFAULT, $1, $2, DEFAULT, DEFAULT, $3, $4) RETURNING `+selectColumns,
		comment.AuthorUserID,
		comment.Body,
		nilIfZero(comment.Object.ThreadID),
		nilIfZero(comment.Object.CampaignID),
	))
}

func nilIfZero(v int64) *int64 {
	if v == 0 {
		return nil
	}
	return &v
}

type DBCommentUpdate struct {
	Body *string
}

// Update updates a comment given its ID.
func (s DBComments) Update(ctx context.Context, id int64, update DBCommentUpdate) (*DBComment, error) {
	if Mocks.Comments.Update != nil {
		return Mocks.Comments.Update(id, update)
	}

	var setFields []*sqlf.Query
	if update.Body != nil {
		setFields = append(setFields, sqlf.Sprintf("body=%s", *update.Body))
	}

	if len(setFields) == 0 {
		return nil, nil
	}
	setFields = append(setFields, sqlf.Sprintf("updated_at=now()"))

	results, err := s.query(ctx, sqlf.Sprintf(`UPDATE comments SET %v WHERE id=%s RETURNING `+selectColumns, sqlf.Join(setFields, ", "), id))
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, ErrCommentNotFound
	}
	return results[0], nil
}

// GetByID retrieves the comment (if any) given its ID.
//
// 🚨 SECURITY: The caller must ensure that the actor is permitted to view this comment.
func (DBComments) GetByID(ctx context.Context, id int64) (*DBComment, error) {
	if Mocks.Comments.GetByID != nil {
		return Mocks.Comments.GetByID(id)
	}

	results, err := DBComments{}.list(ctx, []*sqlf.Query{sqlf.Sprintf("id=%d", id)}, nil)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, ErrCommentNotFound
	}
	return results[0], nil
}

// DBCommentsListOptions contains options for listing comments.
type DBCommentsListOptions struct {
	Query  string // only list comments matching this query (case-insensitively)
	Object types.CommentObject
	*db.LimitOffset
}

func (o DBCommentsListOptions) sqlConditions() []*sqlf.Query {
	conds := []*sqlf.Query{sqlf.Sprintf("TRUE")}
	if o.Query != "" {
		conds = append(conds, sqlf.Sprintf("body ILIKE %s", "%"+o.Query+"%"))
	}
	if o.Object.ThreadID != 0 {
		// TODO!(sqs): add recursion
		conds = append(conds, sqlf.Sprintf("thread_id=%d OR parent_comment_id=(SELECT primary_comment_id FROM threads WHERE id=%d)", o.Object.ThreadID, o.Object.ThreadID))
	}
	if o.Object.CampaignID != 0 {
		conds = append(conds, sqlf.Sprintf("campaign_id=%d OR parent_comment_id=(SELECT primary_comment_id FROM campaigns WHERE id=%d)", o.Object.CampaignID, o.Object.CampaignID))
	}
	return conds
}

// List lists all comments that satisfy the options.
//
// 🚨 SECURITY: The caller must ensure that the actor is permitted to list with the specified
// options.
func (s DBComments) List(ctx context.Context, opt DBCommentsListOptions) ([]*DBComment, error) {
	if Mocks.Comments.List != nil {
		return Mocks.Comments.List(opt)
	}

	return s.list(ctx, opt.sqlConditions(), opt.LimitOffset)
}

func (s DBComments) list(ctx context.Context, conds []*sqlf.Query, limitOffset *db.LimitOffset) ([]*DBComment, error) {
	q := sqlf.Sprintf(`
SELECT `+selectColumns+` FROM comments
WHERE (%s)
ORDER BY id ASC
%s`,
		sqlf.Join(conds, ") AND ("),
		limitOffset.SQL(),
	)
	return s.query(ctx, q)
}

func (DBComments) query(ctx context.Context, query *sqlf.Query) ([]*DBComment, error) {
	rows, err := dbconn.Global.QueryContext(ctx, query.Query(sqlf.PostgresBindVar), query.Args()...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*DBComment
	for rows.Next() {
		t, err := DBComments{}.scanRow(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, t)
	}
	return results, nil
}

func (DBComments) scanRow(row interface {
	Scan(dest ...interface{}) error
}) (*DBComment, error) {
	var t DBComment
	var threadID, campaignID *int64
	if err := row.Scan(
		&t.ID,
		&t.AuthorUserID,
		&t.Body,
		&t.CreatedAt,
		&t.UpdatedAt,
		&threadID,
		&campaignID,
	); err != nil {
		return nil, err
	}
	if threadID != nil {
		t.Object.ThreadID = *threadID
	}
	if campaignID != nil {
		t.Object.CampaignID = *campaignID
	}
	return &t, nil
}

// Count counts all comments that satisfy the options (ignoring limit and offset).
//
// 🚨 SECURITY: The caller must ensure that the actor is permitted to count the comments.
func (DBComments) Count(ctx context.Context, opt DBCommentsListOptions) (int, error) {
	if Mocks.Comments.Count != nil {
		return Mocks.Comments.Count(opt)
	}

	q := sqlf.Sprintf("SELECT COUNT(*) FROM comments WHERE (%s)", sqlf.Join(opt.sqlConditions(), ") AND ("))
	var count int
	if err := dbconn.Global.QueryRowContext(ctx, q.Query(sqlf.PostgresBindVar), q.Args()...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// Delete deletes a comment given its ID.
//
// 🚨 SECURITY: The caller must ensure that the actor is permitted to delete the comment.
func (s DBComments) DeleteByID(ctx context.Context, id int64) error {
	if Mocks.Comments.DeleteByID != nil {
		return Mocks.Comments.DeleteByID(id)
	}
	return s.delete(ctx, sqlf.Sprintf("id=%d", id))
}

func (DBComments) delete(ctx context.Context, cond *sqlf.Query) error {
	conds := []*sqlf.Query{cond, sqlf.Sprintf("TRUE")}
	q := sqlf.Sprintf("DELETE FROM comments WHERE (%s)", sqlf.Join(conds, ") AND ("))

	res, err := dbconn.Global.ExecContext(ctx, q.Query(sqlf.PostgresBindVar), q.Args()...)
	if err != nil {
		return err
	}
	nrows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if nrows == 0 {
		return ErrCommentNotFound
	}
	return nil
}

// mockComments Mocks the comments-related DB operations.
type mockComments struct {
	Create     func(*DBComment) (*DBComment, error)
	Update     func(int64, DBCommentUpdate) (*DBComment, error)
	GetByID    func(int64) (*DBComment, error)
	List       func(DBCommentsListOptions) ([]*DBComment, error)
	Count      func(DBCommentsListOptions) (int, error)
	DeleteByID func(int64) error
}

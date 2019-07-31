package comments

import (
	"context"

	"github.com/graph-gophers/graphql-go"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/graphqlbackend"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/graphqlbackend/graphqlutil"
)

func (GraphQLResolver) Comments(ctx context.Context, arg *graphqlutil.ConnectionArgs) (graphqlbackend.CommentConnection, error) {
	return commentsByOptions(ctx, dbCommentsListOptions{}, arg)
}

func (GraphQLResolver) CommentsInNamespace(ctx context.Context, namespace graphql.ID, arg *graphqlutil.ConnectionArgs) (graphqlbackend.CommentConnection, error) {
	var opt dbCommentsListOptions
	var err error
	opt.NamespaceUserID, opt.NamespaceOrgID, err = graphqlbackend.NamespaceDBIDByID(ctx, namespace)
	if err != nil {
		return nil, err
	}
	return commentsByOptions(ctx, opt, arg)
}

func commentsByOptions(ctx context.Context, opt dbCommentsListOptions, arg *graphqlutil.ConnectionArgs) (graphqlbackend.CommentConnection, error) {
	list, err := dbComments{}.List(ctx, opt)
	if err != nil {
		return nil, err
	}
	comments := make([]*gqlComment, len(list))
	for i, a := range list {
		comments[i] = &gqlComment{db: a}
	}
	return &commentConnection{arg: arg, comments: comments}, nil
}

type commentConnection struct {
	arg       *graphqlutil.ConnectionArgs
	comments []*gqlComment
}

func (r *commentConnection) Nodes(ctx context.Context) ([]graphqlbackend.Comment, error) {
	comments := r.comments
	if first := r.arg.First; first != nil && len(comments) > int(*first) {
		comments = comments[:int(*first)]
	}

	comments2 := make([]graphqlbackend.Comment, len(comments))
	for i, l := range comments {
		comments2[i] = l
	}
	return comments2, nil
}

func (r *commentConnection) TotalCount(ctx context.Context) (int32, error) {
	return int32(len(r.comments)), nil
}

func (r *commentConnection) PageInfo(ctx context.Context) (*graphqlutil.PageInfo, error) {
	return graphqlutil.HasNextPage(r.arg.First != nil && int(*r.arg.First) < len(r.comments)), nil
}

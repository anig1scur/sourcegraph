package sources

import (
	"context"
	"fmt"
	"net/url"
	"sort"

	"github.com/pkg/errors"

	"github.com/sourcegraph/sourcegraph/enterprise/internal/batches/store"
	"github.com/sourcegraph/sourcegraph/internal/actor"
	"github.com/sourcegraph/sourcegraph/internal/batches"
	"github.com/sourcegraph/sourcegraph/internal/database"
	"github.com/sourcegraph/sourcegraph/internal/errcode"
	"github.com/sourcegraph/sourcegraph/internal/extsvc"
	"github.com/sourcegraph/sourcegraph/internal/extsvc/auth"
	"github.com/sourcegraph/sourcegraph/internal/gitserver/protocol"
	"github.com/sourcegraph/sourcegraph/internal/repos"
	"github.com/sourcegraph/sourcegraph/internal/types"
	"github.com/sourcegraph/sourcegraph/internal/vcs"
	"github.com/sourcegraph/sourcegraph/schema"
)

type Sourcer struct {
	sourcer repos.Sourcer
	store   *store.Store
}

type BatchesSource struct {
	repos.ChangesetSource
	repos.UserSource

	au    auth.Authenticator
	store *store.Store
}

// ErrNoPushCredentials is returned by buildCommitOpts if the credentials
// cannot be used by git to authenticate a `git push`.
type ErrNoPushCredentials struct{ credentialsType string }

func (e ErrNoPushCredentials) Error() string {
	return fmt.Sprintf("cannot use credentials of type %s to push commits", e.credentialsType)
}

func (e ErrNoPushCredentials) NonRetryable() bool { return true }

// ErrNoSSHCredential is returned by buildPushConfig if the clone URL of the
// repository uses the ssh:// scheme, but the authenticator doesn't support SSH pushes.
type ErrNoSSHCredential struct{}

func (e ErrNoSSHCredential) Error() string {
	return "The used credential doesn't support SSH pushes, but the repo requires pushing over SSH."
}

func (e ErrNoSSHCredential) NonRetryable() bool { return true }

func (s *BatchesSource) GitserverPushConfig(repo *types.Repo) (*protocol.PushConfig, error) {
	extSvcType := repo.ExternalRepo.ServiceType
	cloneURL, err := extractCloneURL(repo)
	if err != nil {
		return nil, err
	}
	if s.au == nil {
		// This is OK: we'll just send no key and gitserver will use
		// the keys installed locally for SSH and the token from the
		// clone URL for https.
		// This path is only triggered when `loadAuthenticator` returns
		// nil, which is only the case for site-admins currently.
		// We want to revisit this once we start disabling usage of global
		// credentials altogether in RFC312.
		return &protocol.PushConfig{RemoteURL: cloneURL}, nil
	}

	u, err := vcs.ParseURL(cloneURL)
	if err != nil {
		return nil, errors.Wrap(err, "parsing repository clone URL")
	}

	// If the repo is cloned using SSH, we need to pass along a private key and passphrase.
	if u.Scheme == "ssh" {
		sshA, ok := s.au.(auth.AuthenticatorWithSSH)
		if !ok {
			return nil, ErrNoSSHCredential{}
		}
		privateKey, passphrase := sshA.SSHPrivateKey()
		return &protocol.PushConfig{
			RemoteURL:  cloneURL,
			PrivateKey: privateKey,
			Passphrase: passphrase,
		}, nil
	}

	switch av := s.au.(type) {
	case *auth.OAuthBearerTokenWithSSH:
		if err := setOAuthTokenAuth(u, extSvcType, av.Token); err != nil {
			return nil, err
		}
	case *auth.OAuthBearerToken:
		if err := setOAuthTokenAuth(u, extSvcType, av.Token); err != nil {
			return nil, err
		}

	case *auth.BasicAuthWithSSH:
		if err := setBasicAuth(u, extSvcType, av.Username, av.Password); err != nil {
			return nil, err
		}
	case *auth.BasicAuth:
		if err := setBasicAuth(u, extSvcType, av.Username, av.Password); err != nil {
			return nil, err
		}
	default:
		return nil, ErrNoPushCredentials{credentialsType: fmt.Sprintf("%T", s.au)}
	}

	return &protocol.PushConfig{RemoteURL: u.String()}, nil
}

func setOAuthTokenAuth(u *url.URL, extsvcType, token string) error {
	switch extsvcType {
	case extsvc.TypeGitHub:
		u.User = url.User(token)

	case extsvc.TypeGitLab:
		u.User = url.UserPassword("git", token)

	case extsvc.TypeBitbucketServer:
		return errors.New("require username/token to push commits to BitbucketServer")
	}
	return nil
}

func setBasicAuth(u *url.URL, extSvcType, username, password string) error {
	switch extSvcType {
	case extsvc.TypeGitHub, extsvc.TypeGitLab:
		return errors.New("need token to push commits to " + extSvcType)

	case extsvc.TypeBitbucketServer:
		u.User = url.UserPassword(username, password)
	}
	return nil
}

// extractCloneURL returns a remote URL, preferring SSH over HTTPS.
func extractCloneURL(repo *types.Repo) (string, error) {
	if len(repo.Sources) == 0 {
		return "", errors.New("no clone URL found for repo")
	}
	sources := make([]*types.SourceInfo, 0, len(repo.Sources))
	for _, source := range repo.Sources {
		sources = append(sources, source)
	}
	sort.SliceStable(sources, func(i, j int) bool {
		parsedURL, err := vcs.ParseURL(sources[i].CloneURL)
		if err != nil {
			return false
		}
		if parsedURL.Scheme == "ssh" || parsedURL.Scheme == "" {
			return false
		}
		return true
	})
	cloneURL := sources[0].CloneURL
	// TODO: Do this once we don't want to use existing credentials anymore.
	// parsedU, err := vcs.ParseURL(cloneURL)
	// if err != nil {
	// 	return "", err
	// }
	// // Remove any existing credentials from the clone URL.
	// parsedU.User = nil
	// return parsedU.String(), nil
	return cloneURL, nil
}

func NewSourcer(sourcer repos.Sourcer, store *store.Store) *Sourcer {
	return &Sourcer{
		sourcer,
		store,
	}
}

func (s *Sourcer) ForChangeset(ctx context.Context, ch *batches.Changeset) (*BatchesSource, error) {
	repo, err := s.store.Repos().Get(ctx, ch.RepoID)
	if err != nil {
		return nil, errors.Wrap(err, "loading changeset repo")
	}
	return s.ForRepo(ctx, repo)
}

func (s *Sourcer) ForRepo(ctx context.Context, repo *types.Repo) (*BatchesSource, error) {
	return s.loadExternalService(ctx, database.ExternalServicesListOptions{
		// Consider all available external services for this repo.
		IDs: repo.ExternalServiceIDs(),
	})
}

func (s *Sourcer) ForExternalService(ctx context.Context, opts store.GetExternalServiceIDOpts) (*BatchesSource, error) {
	extSvcIDs, err := s.store.GetExternalServiceIDs(ctx, opts)
	if err != nil {
		return nil, errors.Wrap(err, "loading external service IDs")
	}
	return s.loadExternalService(ctx, database.ExternalServicesListOptions{
		IDs: extSvcIDs,
	})
}

func (s *Sourcer) FromRepoSource(src repos.Source) (*BatchesSource, error) {
	return batchesSourceFromRepoSource(src, s.store)
}

func (s *Sourcer) loadExternalService(ctx context.Context, opts database.ExternalServicesListOptions) (*BatchesSource, error) {
	extSvc, err := loadExternalService(ctx, s.store.ExternalServices(), opts)
	if err != nil {
		return nil, errors.Wrap(err, "loading external service")
	}
	css, err := buildChangesetSource(s.sourcer, s.store, extSvc)
	if err != nil {
		return nil, errors.Wrap(err, "building changeset source")
	}
	// TODO: This should be the default, once we don't use external service tokens anymore.
	// cred, err := loadSiteCredential(ctx, s.store, repo)
	// if err != nil {
	// 	return nil, err
	// }
	// if cred != nil {
	// 	return s.WithAuthenticator(css, cred)
	// }
	return css, nil
}

func (s *BatchesSource) WithAuthenticatorForActor(ctx context.Context, repo *types.Repo) (*BatchesSource, error) {
	act := actor.FromContext(ctx)
	if !act.IsAuthenticated() {
		return nil, errors.New("cannot get authenticator from actor: no user in context")
	}
	return s.WithAuthenticatorForUser(ctx, act.UID, repo)
}

func (s *BatchesSource) WithAuthenticatorForUser(ctx context.Context, userID int32, repo *types.Repo) (*BatchesSource, error) {
	cred, err := loadUserCredential(ctx, s.store, userID, repo)
	if err != nil {
		return nil, errors.Wrap(err, "loading user credential")
	}
	if cred != nil {
		return s.WithAuthenticator(cred)
	}

	cred, err = loadSiteCredential(ctx, s.store, repo)
	if err != nil {
		return nil, errors.Wrap(err, "loading site credential")
	}
	if cred != nil {
		return s.WithAuthenticator(cred)
	}
	// For now, default to the internal authenticator of the source.
	// This is either a site-credential or the external service token.

	// If neither exist, we need to check if the user is an admin: if they are,
	// then we can use the nil return from loadUserCredential() to fall
	// back to the global credentials used for the code host. If
	// not, then we need to error out.
	// Once we tackle https://github.com/sourcegraph/sourcegraph/issues/16814,
	// this code path should be removed.
	user, err := database.UsersWith(s.store).GetByID(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load user")
	}
	if user.SiteAdmin {
		return s, nil
	}

	// Otherwise, we can't authenticate the given ChangesetSource, so we need to bail out.
	return nil, &ErrMissingCredentials{repo: string(repo.Name)}
}

// WithSiteAuthenticator uses the site credential of the code host of the passed-in repo.
// If no credential is found, the original source is returned and uses the external service
// config.
func (s *BatchesSource) WithSiteAuthenticator(ctx context.Context, repo *types.Repo) (*BatchesSource, error) {
	cred, err := loadSiteCredential(ctx, s.store, repo)
	if err != nil {
		return nil, errors.Wrap(err, "loading site credential")
	}
	if cred != nil {
		return s.WithAuthenticator(cred)
	}
	return s, nil
}

// ErrMissingCredentials is returned by loadAuthenticator if the user that
// applied the last batch  change/changeset spec doesn't have UserCredentials for
// the given repository and is not a site-admin (so no fallback to the global
// credentials is possible).
type ErrMissingCredentials struct{ repo string }

func (e ErrMissingCredentials) Error() string {
	return fmt.Sprintf("user does not have a valid credential for repository %q", e.repo)
}

func (e ErrMissingCredentials) NonRetryable() bool { return true }

func (s *BatchesSource) WithAuthenticator(au auth.Authenticator) (*BatchesSource, error) {
	return authenticateChangesetSource(s, au)
}

// loadExternalService looks up all external services that are connected to the given repo.
// The first external service to have a token configured will be returned then.
// If no external service matching the above criteria is found, an error is returned.
func loadExternalService(ctx context.Context, s *database.ExternalServiceStore, opts database.ExternalServicesListOptions) (*types.ExternalService, error) {
	es, err := s.List(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Sort the external services so user owned external service go last.
	// This also retains the initial ORDER BY ID DESC.
	sort.SliceStable(es, func(i, j int) bool {
		return es[i].NamespaceUserID == 0 && es[i].ID > es[j].ID
	})

	for _, e := range es {
		cfg, err := e.Configuration()
		if err != nil {
			return nil, err
		}

		switch cfg := cfg.(type) {
		case *schema.GitHubConnection:
			if cfg.Token != "" {
				return e, nil
			}
		case *schema.BitbucketServerConnection:
			if cfg.Token != "" {
				return e, nil
			}
		case *schema.GitLabConnection:
			if cfg.Token != "" {
				return e, nil
			}
		}
	}

	return nil, errors.New("no external services found")
}

// buildChangesetSource get an authenticated ChangesetSource for the given repo
// to load the changeset state from.
func buildChangesetSource(sourcer repos.Sourcer, store *store.Store, externalService *types.ExternalService) (*BatchesSource, error) {
	// Then, use the external service to build a ChangesetSource.
	sources, err := sourcer(externalService)
	if err != nil {
		return nil, err
	}
	if len(sources) != 1 {
		return nil, fmt.Errorf("got no Source for external service of kind %q", externalService.Kind)
	}
	source := sources[0]
	return batchesSourceFromRepoSource(source, store)
}

func batchesSourceFromRepoSource(src repos.Source, store *store.Store) (*BatchesSource, error) {
	css, ok := src.(repos.ChangesetSource)
	if !ok {
		return nil, fmt.Errorf("cannot create ChangesetSource from external service")
	}
	us, ok := src.(repos.UserSource)
	if !ok {
		return nil, fmt.Errorf("cannot create UserSource from external service")
	}
	return &BatchesSource{
		ChangesetSource: css,
		UserSource:      us,
		store:           store,
	}, nil
}

func authenticateChangesetSource(src *BatchesSource, au auth.Authenticator) (*BatchesSource, error) {
	repoSource, err := src.UserSource.WithAuthenticator(au)
	if err != nil {
		return nil, err
	}
	src.au = au
	src.ChangesetSource = repoSource.(repos.ChangesetSource)
	src.UserSource = repoSource.(repos.UserSource)
	return src, nil
}

func loadUserCredential(ctx context.Context, s *store.Store, userID int32, repo *types.Repo) (auth.Authenticator, error) {
	cred, err := s.UserCredentials().GetByScope(ctx, database.UserCredentialScope{
		Domain:              database.UserCredentialDomainBatches,
		UserID:              userID,
		ExternalServiceType: repo.ExternalRepo.ServiceType,
		ExternalServiceID:   repo.ExternalRepo.ServiceID,
	})
	if err != nil && !errcode.IsNotFound(err) {
		return nil, err
	}
	if cred != nil {
		return cred.Credential, nil
	}
	return nil, nil
}

func loadSiteCredential(ctx context.Context, s *store.Store, repo *types.Repo) (auth.Authenticator, error) {
	cred, err := s.GetSiteCredential(ctx, store.GetSiteCredentialOpts{
		ExternalServiceType: repo.ExternalRepo.ServiceType,
		ExternalServiceID:   repo.ExternalRepo.ServiceID,
	})
	if err != nil && err != store.ErrNoResults {
		return nil, err
	}
	if cred != nil {
		return cred.Credential, nil
	}
	return nil, nil
}

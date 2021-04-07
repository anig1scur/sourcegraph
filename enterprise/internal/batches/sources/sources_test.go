package sources

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/sourcegraph/sourcegraph/internal/api"
	"github.com/sourcegraph/sourcegraph/internal/database"
	"github.com/sourcegraph/sourcegraph/internal/extsvc"
	"github.com/sourcegraph/sourcegraph/internal/extsvc/auth"
	"github.com/sourcegraph/sourcegraph/internal/gitserver/protocol"
	"github.com/sourcegraph/sourcegraph/internal/types"
)

func TestExtractCloneURL(t *testing.T) {
	t.Parallel()

	tcs := []struct {
		name      string
		want      string
		cloneURLs []string
	}{
		{
			name:      "https",
			want:      "https://secrettoken@github.com/sourcegraph/sourcegraph",
			cloneURLs: []string{"https://secrettoken@github.com/sourcegraph/sourcegraph"},
		},
		{
			name:      "https user password",
			want:      "https://git:secrettoken@github.com/sourcegraph/sourcegraph",
			cloneURLs: []string{"https://git:secrettoken@github.com/sourcegraph/sourcegraph"},
		},
		{
			name:      "ssh no protocol specified",
			want:      "ssh://git@github.com/sourcegraph/sourcegraph.git",
			cloneURLs: []string{"git@github.com:sourcegraph/sourcegraph.git"},
		},
		{
			name:      "ssh protocol specified",
			want:      "ssh://git@github.com/sourcegraph/sourcegraph.git",
			cloneURLs: []string{"ssh://git@github.com/sourcegraph/sourcegraph.git"},
		},
		{
			name: "https and ssh, favoring https",
			want: "https://secrettoken@github.com/sourcegraph/sourcegraph",
			cloneURLs: []string{
				"https://secrettoken@github.com/sourcegraph/sourcegraph",
				"git@github.com:sourcegraph/sourcegraph.git",
				"ssh://git@github.com/sourcegraph/sourcegraph.git",
			},
		},
		{
			name: "https and ssh, favoring https different order",
			want: "https://secrettoken@github.com/sourcegraph/sourcegraph",
			cloneURLs: []string{
				"git@github.com:sourcegraph/sourcegraph.git",
				"ssh://git@github.com/sourcegraph/sourcegraph.git",
				"https://secrettoken@github.com/sourcegraph/sourcegraph",
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			repo := &types.Repo{
				Sources: map[string]*types.SourceInfo{},
			}
			for _, cloneURL := range tc.cloneURLs {
				repo.Sources[cloneURL] = &types.SourceInfo{
					CloneURL: cloneURL,
				}
			}
			have, err := extractCloneURL(repo)
			if err != nil {
				t.Fatal(err)
			}
			if have != tc.want {
				t.Fatalf("invalid cloneURL returned, want=%q have=%q", tc.want, have)
			}
		})
	}
}

// func TestLoadChangesetSource(t *testing.T) {
// 	ctx := context.Background()
// 	sourcer := repos.NewSourcer(httpcli.NewFactory(
// 		func(cli httpcli.Doer) httpcli.Doer {
// 			return httpcli.DoerFunc(func(req *http.Request) (*http.Response, error) {
// 				// Don't actually execute the request, just dump the authorization header
// 				// in the error, so we can assert on it further down.
// 				return nil, errors.New(req.Header.Get("Authorization"))
// 			})
// 		},
// 		httpcli.NewTimeoutOpt(1*time.Second),
// 	))

// 	externalService := types.ExternalService{
// 		ID:          1,
// 		Kind:        extsvc.KindGitHub,
// 		DisplayName: "GitHub.com",
// 		Config:      `{"url": "https://github.com", "token": "123", "authorization": {}}`,
// 	}
// 	repo := &types.Repo{
// 		Name:    api.RepoName("test-repo"),
// 		URI:     "test-repo",
// 		Private: true,
// 		ExternalRepo: api.ExternalRepoSpec{
// 			ID:          "external-id-123",
// 			ServiceType: extsvc.TypeGitHub,
// 			ServiceID:   "https://github.com/",
// 		},
// 		Sources: map[string]*types.SourceInfo{
// 			externalService.URN(): {
// 				ID:       externalService.URN(),
// 				CloneURL: "https://123@github.com/sourcegraph/sourcegraph",
// 			},
// 		},
// 	}

// 	// Store mocks.
// 	database.Mocks.ExternalServices.List = func(opt database.ExternalServicesListOptions) ([]*types.ExternalService, error) {
// 		return []*types.ExternalService{&externalService}, nil
// 	}
// 	t.Cleanup(func() {
// 		database.Mocks.ExternalServices.List = nil
// 	})
// 	hasCredential := false
// 	syncStore := &MockSyncStore{
// 		getSiteCredential: func(ctx context.Context, opts store.GetSiteCredentialOpts) (*store.SiteCredential, error) {
// 			if hasCredential {
// 				return &store.SiteCredential{Credential: &auth.OAuthBearerToken{Token: "456"}}, nil
// 			}
// 			return nil, store.ErrNoResults
// 		},
// 	}

// 	// If no site-credential exists, the token from the external service should be used.
// 	src, err := loadChangesetSource(ctx, sourcer, syncStore, repo)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if err := src.(*repos.GithubSource).ValidateAuthenticator(ctx); err == nil {
// 		t.Fatal("unexpected nil error")
// 	} else if have, want := err.Error(), "Bearer 123"; have != want {
// 		t.Fatalf("invalid token used, want=%q have=%q", want, have)
// 	}

// 	// If one exists, prefer that one over the external service config ones.
// 	hasCredential = true
// 	src, err = loadChangesetSource(ctx, sourcer, syncStore, repo)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if err := src.(*repos.GithubSource).ValidateAuthenticator(ctx); err == nil {
// 		t.Fatal("unexpected nil error")
// 	} else if have, want := err.Error(), "Bearer 456"; have != want {
// 		t.Fatalf("invalid token used, want=%q have=%q", want, have)
// 	}
// }

func TestLoadExternalService(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	noToken := types.ExternalService{
		ID:          1,
		Kind:        extsvc.KindGitHub,
		DisplayName: "GitHub no token",
		Config:      `{"url": "https://github.com", "authorization": {}}`,
	}
	userOwnedWithToken := types.ExternalService{
		ID:              2,
		Kind:            extsvc.KindGitHub,
		DisplayName:     "GitHub user owned",
		NamespaceUserID: 1234,
		Config:          `{"url": "https://github.com", "token": "123", "authorization": {}}`,
	}
	withToken := types.ExternalService{
		ID:          3,
		Kind:        extsvc.KindGitHub,
		DisplayName: "GitHub token",
		Config:      `{"url": "https://github.com", "token": "123", "authorization": {}}`,
	}
	withTokenNewer := types.ExternalService{
		ID:          4,
		Kind:        extsvc.KindGitHub,
		DisplayName: "GitHub newer token",
		Config:      `{"url": "https://github.com", "token": "123456", "authorization": {}}`,
	}

	repo := &types.Repo{
		Name:    api.RepoName("test-repo"),
		URI:     "test-repo",
		Private: true,
		ExternalRepo: api.ExternalRepoSpec{
			ID:          "external-id-123",
			ServiceType: extsvc.TypeGitHub,
			ServiceID:   "https://github.com/",
		},
		Sources: map[string]*types.SourceInfo{
			noToken.URN(): {
				ID:       noToken.URN(),
				CloneURL: "https://github.com/sourcegraph/sourcegraph",
			},
			userOwnedWithToken.URN(): {
				ID:       userOwnedWithToken.URN(),
				CloneURL: "https://123@github.com/sourcegraph/sourcegraph",
			},
			withToken.URN(): {
				ID:       withToken.URN(),
				CloneURL: "https://123@github.com/sourcegraph/sourcegraph",
			},
			withTokenNewer.URN(): {
				ID:       withTokenNewer.URN(),
				CloneURL: "https://123456@github.com/sourcegraph/sourcegraph",
			},
		},
	}

	database.Mocks.ExternalServices.List = func(opt database.ExternalServicesListOptions) ([]*types.ExternalService, error) {
		sources := make([]*types.ExternalService, 0)
		if _, ok := repo.Sources[noToken.URN()]; ok {
			sources = append(sources, &noToken)
		}
		if _, ok := repo.Sources[userOwnedWithToken.URN()]; ok {
			sources = append(sources, &userOwnedWithToken)
		}
		if _, ok := repo.Sources[withToken.URN()]; ok {
			sources = append(sources, &withToken)
		}
		if _, ok := repo.Sources[withTokenNewer.URN()]; ok {
			sources = append(sources, &withTokenNewer)
		}
		return sources, nil
	}
	t.Cleanup(func() {
		database.Mocks.ExternalServices.List = nil
	})

	// Expect the newest public external service with a token to be returned.
	svc, err := loadExternalService(ctx, &database.ExternalServiceStore{}, database.ExternalServicesListOptions{IDs: repo.ExternalServiceIDs()})
	if err != nil {
		t.Fatalf("invalid error, expected nil, got %v", err)
	}
	if have, want := svc.ID, withTokenNewer.ID; have != want {
		t.Fatalf("invalid external service returned, want=%d have=%d", want, have)
	}

	// Now delete the global external services and expect the user owned external service to be returned.
	delete(repo.Sources, withTokenNewer.URN())
	delete(repo.Sources, withToken.URN())
	svc, err = loadExternalService(ctx, &database.ExternalServiceStore{}, database.ExternalServicesListOptions{IDs: repo.ExternalServiceIDs()})
	if err != nil {
		t.Fatalf("invalid error, expected nil, got %v", err)
	}
	if have, want := svc.ID, userOwnedWithToken.ID; have != want {
		t.Fatalf("invalid external service returned, want=%d have=%d", want, have)
	}
}

func TestBatchesSource_GitserverPushConfig(t *testing.T) {
	t.Parallel()

	oauthHTTPSAuthenticator := auth.OAuthBearerToken{Token: "bearer-test"}
	oauthSSHAuthenticator := auth.OAuthBearerTokenWithSSH{
		OAuthBearerToken: oauthHTTPSAuthenticator,
		PrivateKey:       "private-key",
		Passphrase:       "passphrase",
		PublicKey:        "public-key",
	}
	basicHTTPSAuthenticator := auth.BasicAuth{Username: "basic", Password: "pw"}
	basicSSHAuthenticator := auth.BasicAuthWithSSH{
		BasicAuth:  basicHTTPSAuthenticator,
		PrivateKey: "private-key",
		Passphrase: "passphrase",
		PublicKey:  "public-key",
	}
	tcs := []struct {
		name                string
		externalServiceType string
		cloneURL            string
		authenticator       auth.Authenticator
		wantPushConfig      *protocol.PushConfig
		wantErr             error
	}{
		// Without authenticator:
		{
			name:                "GitHub HTTPS no token",
			externalServiceType: extsvc.TypeGitHub,
			cloneURL:            "https://github.com/sourcegraph/sourcegraph",
			wantPushConfig: &protocol.PushConfig{
				RemoteURL: "https://github.com/sourcegraph/sourcegraph",
			},
		},
		{
			name:                "GitHub HTTPS token",
			externalServiceType: extsvc.TypeGitHub,
			cloneURL:            "https://token@github.com/sourcegraph/sourcegraph",
			wantPushConfig: &protocol.PushConfig{
				RemoteURL: "https://token@github.com/sourcegraph/sourcegraph",
			},
		},
		{
			name:                "GitHub SSH",
			externalServiceType: extsvc.TypeGitHub,
			cloneURL:            "git@github.com:sourcegraph/sourcegraph.git",
			wantPushConfig: &protocol.PushConfig{
				RemoteURL: "ssh://git@github.com/sourcegraph/sourcegraph.git",
			},
		},
		{
			name:                "GitLab HTTPS no token",
			externalServiceType: extsvc.TypeGitLab,
			cloneURL:            "https://gitlab.com/sourcegraph/sourcegraph",
			wantPushConfig: &protocol.PushConfig{
				RemoteURL: "https://gitlab.com/sourcegraph/sourcegraph",
			},
		},
		{
			name:                "GitLab HTTPS token",
			externalServiceType: extsvc.TypeGitLab,
			cloneURL:            "https://git:token@gitlab.com/sourcegraph/sourcegraph",
			wantPushConfig: &protocol.PushConfig{
				RemoteURL: "https://git:token@gitlab.com/sourcegraph/sourcegraph",
			},
		},
		{
			name:                "GitLab SSH",
			externalServiceType: extsvc.TypeGitLab,
			cloneURL:            "git@gitlab.com:sourcegraph/sourcegraph.git",
			wantPushConfig: &protocol.PushConfig{
				RemoteURL: "ssh://git@gitlab.com/sourcegraph/sourcegraph.git",
			},
		},
		{
			name:                "Bitbucket server HTTPS no token",
			externalServiceType: extsvc.TypeBitbucketServer,
			cloneURL:            "https://bitbucket.sgdev.org/sourcegraph/sourcegraph",
			wantPushConfig: &protocol.PushConfig{
				RemoteURL: "https://bitbucket.sgdev.org/sourcegraph/sourcegraph",
			},
		},
		{
			name:                "Bitbucket server HTTPS token",
			externalServiceType: extsvc.TypeBitbucketServer,
			cloneURL:            "https://token@bitbucket.sgdev.org/sourcegraph/sourcegraph",
			wantPushConfig: &protocol.PushConfig{
				RemoteURL: "https://token@bitbucket.sgdev.org/sourcegraph/sourcegraph",
			},
		},
		{
			name:                "Bitbucket server SSH",
			externalServiceType: extsvc.TypeBitbucketServer,
			cloneURL:            "ssh://git@bitbucket.sgdev.org:7999/sourcegraph/sourcegraph",
			wantPushConfig: &protocol.PushConfig{
				RemoteURL: "ssh://git@bitbucket.sgdev.org:7999/sourcegraph/sourcegraph",
			},
		},
		// With authenticator:
		{
			name:                "GitHub HTTPS no token with authenticator",
			externalServiceType: extsvc.TypeGitHub,
			cloneURL:            "https://github.com/sourcegraph/sourcegraph",
			authenticator:       &oauthHTTPSAuthenticator,
			wantPushConfig: &protocol.PushConfig{
				RemoteURL: "https://bearer-test@github.com/sourcegraph/sourcegraph",
			},
		},
		{
			name:                "GitHub HTTPS token with authenticator",
			externalServiceType: extsvc.TypeGitHub,
			cloneURL:            "https://token@github.com/sourcegraph/sourcegraph",
			authenticator:       &oauthHTTPSAuthenticator,
			wantPushConfig: &protocol.PushConfig{
				RemoteURL: "https://bearer-test@github.com/sourcegraph/sourcegraph",
			},
		},
		{
			name:                "GitHub SSH with authenticator",
			externalServiceType: extsvc.TypeGitHub,
			cloneURL:            "git@github.com:sourcegraph/sourcegraph.git",
			authenticator:       &oauthSSHAuthenticator,
			wantPushConfig: &protocol.PushConfig{
				RemoteURL:  "ssh://git@github.com/sourcegraph/sourcegraph.git",
				PrivateKey: "private-key",
				Passphrase: "passphrase",
			},
		},
		{
			name:                "GitLab HTTPS no token with authenticator",
			externalServiceType: extsvc.TypeGitLab,
			cloneURL:            "https://gitlab.com/sourcegraph/sourcegraph",
			authenticator:       &oauthHTTPSAuthenticator,
			wantPushConfig: &protocol.PushConfig{
				RemoteURL: "https://git:bearer-test@gitlab.com/sourcegraph/sourcegraph",
			},
		},
		{
			name:                "GitLab HTTPS token with authenticator",
			externalServiceType: extsvc.TypeGitLab,
			cloneURL:            "https://git:token@gitlab.com/sourcegraph/sourcegraph",
			authenticator:       &oauthHTTPSAuthenticator,
			wantPushConfig: &protocol.PushConfig{
				RemoteURL: "https://git:bearer-test@gitlab.com/sourcegraph/sourcegraph",
			},
		},
		{
			name:                "GitLab SSH with authenticator",
			externalServiceType: extsvc.TypeGitLab,
			cloneURL:            "git@gitlab.com:sourcegraph/sourcegraph.git",
			authenticator:       &oauthSSHAuthenticator,
			wantPushConfig: &protocol.PushConfig{
				RemoteURL:  "ssh://git@gitlab.com/sourcegraph/sourcegraph.git",
				PrivateKey: "private-key",
				Passphrase: "passphrase",
			},
		},
		{
			name:                "Bitbucket server HTTPS no token with authenticator",
			externalServiceType: extsvc.TypeBitbucketServer,
			cloneURL:            "https://bitbucket.sgdev.org/sourcegraph/sourcegraph",
			authenticator:       &basicHTTPSAuthenticator,
			wantPushConfig: &protocol.PushConfig{
				RemoteURL: "https://basic:pw@bitbucket.sgdev.org/sourcegraph/sourcegraph",
			},
		},
		{
			name:                "Bitbucket server HTTPS token with authenticator",
			externalServiceType: extsvc.TypeBitbucketServer,
			cloneURL:            "https://token@bitbucket.sgdev.org/sourcegraph/sourcegraph",
			authenticator:       &basicHTTPSAuthenticator,
			wantPushConfig: &protocol.PushConfig{
				RemoteURL: "https://basic:pw@bitbucket.sgdev.org/sourcegraph/sourcegraph",
			},
		},
		{
			name:                "Bitbucket server SSH with authenticator",
			externalServiceType: extsvc.TypeBitbucketServer,
			cloneURL:            "ssh://git@bitbucket.sgdev.org:7999/sourcegraph/sourcegraph",
			authenticator:       &basicSSHAuthenticator,
			wantPushConfig: &protocol.PushConfig{
				RemoteURL:  "ssh://git@bitbucket.sgdev.org:7999/sourcegraph/sourcegraph",
				PrivateKey: "private-key",
				Passphrase: "passphrase",
			},
		},
		// Errors
		{
			name:                "Bitbucket server SSH no keypair",
			externalServiceType: extsvc.TypeBitbucketServer,
			cloneURL:            "ssh://git@bitbucket.sgdev.org:7999/sourcegraph/sourcegraph",
			authenticator:       &basicHTTPSAuthenticator,
			wantErr:             ErrNoSSHCredential{},
		},
		{
			name:                "Invalid credential type",
			externalServiceType: extsvc.TypeGitHub,
			cloneURL:            "https://github.com/sourcegraph/sourcegraph",
			authenticator:       &auth.OAuthClient{},
			wantErr:             ErrNoPushCredentials{credentialsType: "*auth.OAuthClient"},
		},
	}
	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			src := &BatchesSource{
				au: tt.authenticator,
			}
			repo := &types.Repo{
				ExternalRepo: api.ExternalRepoSpec{
					ServiceType: tt.externalServiceType,
				},
				Sources: map[string]*types.SourceInfo{tt.cloneURL: {CloneURL: tt.cloneURL}},
			}
			havePushConfig, haveErr := src.GitserverPushConfig(repo)
			if haveErr != tt.wantErr {
				t.Fatalf("invalid error returned, want=%v have=%v", tt.wantErr, haveErr)
			}
			if diff := cmp.Diff(havePushConfig, tt.wantPushConfig); diff != "" {
				t.Fatalf("invalid push config returned: %s", diff)
			}
		})
	}
}

// func TestLoadAuthenticator(t *testing.T) {
// 	ctx := backend.WithAuthzBypass(context.Background())
// 	db := dbtesting.GetDB(t)
// 	token := &auth.OAuthBearerToken{Token: "abcdef"}

// 	cstore := store.New(db)

// 	admin := ct.CreateTestUser(t, db, true)
// 	user := ct.CreateTestUser(t, db, false)

// 	rs, _ := ct.CreateTestRepos(t, ctx, db, 1)
// 	repo := rs[0]

// 	batchSpec := ct.CreateBatchSpec(t, ctx, cstore, "reconciler-test-batch-change", admin.ID)
// 	adminBatchChange := ct.CreateBatchChange(t, ctx, cstore, "reconciler-test-batch-change", admin.ID, batchSpec.ID)
// 	userBatchChange := ct.CreateBatchChange(t, ctx, cstore, "reconciler-test-batch-change", user.ID, batchSpec.ID)

// 	t.Run("imported changeset uses global token when no site-credential exists", func(t *testing.T) {
// 		a, err := loadAuthenticator(ctx, cstore, &batches.Changeset{
// 			OwnedByBatchChangeID: 0,
// 		}, repo)
// 		if err != nil {
// 			t.Errorf("unexpected non-nil error: %v", err)
// 		}
// 		if a != nil {
// 			t.Errorf("unexpected non-nil authenticator: %v", a)
// 		}
// 	})

// 	t.Run("imported changeset uses site-credential when exists", func(t *testing.T) {
// 		if err := cstore.CreateSiteCredential(ctx, &store.SiteCredential{
// 			ExternalServiceType: repo.ExternalRepo.ServiceType,
// 			ExternalServiceID:   repo.ExternalRepo.ServiceID,
// 			Credential:          token,
// 		}); err != nil {
// 			t.Fatal(err)
// 		}
// 		t.Cleanup(func() {
// 			ct.TruncateTables(t, db, "batch_changes_site_credentials")
// 		})

// 		a, err := loadAuthenticator(ctx, cstore, &batches.Changeset{
// 			OwnedByBatchChangeID: 0,
// 		}, repo)
// 		if err != nil {
// 			t.Errorf("unexpected non-nil error: %v", err)
// 		}
// 		if diff := cmp.Diff(token, a); diff != "" {
// 			t.Errorf("unexpected authenticator:\n%s", diff)
// 		}
// 	})

// 	t.Run("owned by missing batch change", func(t *testing.T) {
// 		_, err := loadAuthenticator(ctx, cstore, &batches.Changeset{
// 			OwnedByBatchChangeID: 1234,
// 		}, repo)
// 		if err == nil {
// 			t.Error("unexpected nil error")
// 		}
// 	})

// 	t.Run("owned by admin user without credential", func(t *testing.T) {
// 		a, err := loadAuthenticator(ctx, cstore, &batches.Changeset{
// 			OwnedByBatchChangeID: adminBatchChange.ID,
// 		}, repo)
// 		if err != nil {
// 			t.Errorf("unexpected non-nil error: %v", err)
// 		}
// 		if a != nil {
// 			t.Errorf("unexpected non-nil authenticator: %v", a)
// 		}
// 	})

// 	t.Run("owned by normal user without credential", func(t *testing.T) {
// 		_, err := loadAuthenticator(ctx, cstore, &batches.Changeset{
// 			OwnedByBatchChangeID: userBatchChange.ID,
// 		}, repo)
// 		if err == nil {
// 			t.Error("unexpected nil error")
// 		}
// 	})

// 	t.Run("owned by admin user with credential", func(t *testing.T) {
// 		if _, err := cstore.UserCredentials().Create(ctx, database.UserCredentialScope{
// 			Domain:              database.UserCredentialDomainBatches,
// 			UserID:              admin.ID,
// 			ExternalServiceType: repo.ExternalRepo.ServiceType,
// 			ExternalServiceID:   repo.ExternalRepo.ServiceID,
// 		}, token); err != nil {
// 			t.Fatal(err)
// 		}

// 		a, err := loadAuthenticator(ctx, cstore, &batches.Changeset{
// 			OwnedByBatchChangeID: adminBatchChange.ID,
// 		}, repo)
// 		if err != nil {
// 			t.Errorf("unexpected non-nil error: %v", err)
// 		}
// 		if diff := cmp.Diff(token, a); diff != "" {
// 			t.Errorf("unexpected authenticator:\n%s", diff)
// 		}
// 	})

// 	t.Run("owned by normal user with credential", func(t *testing.T) {
// 		if _, err := cstore.UserCredentials().Create(ctx, database.UserCredentialScope{
// 			Domain:              database.UserCredentialDomainBatches,
// 			UserID:              user.ID,
// 			ExternalServiceType: repo.ExternalRepo.ServiceType,
// 			ExternalServiceID:   repo.ExternalRepo.ServiceID,
// 		}, token); err != nil {
// 			t.Fatal(err)
// 		}
// 		t.Cleanup(func() {
// 			ct.TruncateTables(t, db, "user_credentials")
// 		})

// 		a, err := loadAuthenticator(ctx, cstore, &batches.Changeset{
// 			OwnedByBatchChangeID: userBatchChange.ID,
// 		}, repo)
// 		if err != nil {
// 			t.Errorf("unexpected non-nil error: %v", err)
// 		}
// 		if diff := cmp.Diff(token, a); diff != "" {
// 			t.Errorf("unexpected authenticator:\n%s", diff)
// 		}
// 	})

// 	t.Run("owned by user without credential falls back to site-credential", func(t *testing.T) {
// 		if err := cstore.CreateSiteCredential(ctx, &store.SiteCredential{
// 			ExternalServiceType: repo.ExternalRepo.ServiceType,
// 			ExternalServiceID:   repo.ExternalRepo.ServiceID,
// 			Credential:          token,
// 		}); err != nil {
// 			t.Fatal(err)
// 		}
// 		t.Cleanup(func() {
// 			ct.TruncateTables(t, db, "batch_changes_site_credentials")
// 		})

// 		a, err := loadAuthenticator(ctx, cstore, &batches.Changeset{
// 			OwnedByBatchChangeID: userBatchChange.ID,
// 		}, repo)
// 		if err != nil {
// 			t.Errorf("unexpected non-nil error: %v", err)
// 		}
// 		if diff := cmp.Diff(token, a); diff != "" {
// 			t.Errorf("unexpected authenticator:\n%s", diff)
// 		}
// 	})
// }

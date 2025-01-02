package httpz

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gofrs/uuid/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/securecookie"
	"github.com/jackc/errortree"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgxutil"
	"github.com/jackc/structify"
	"github.com/jackc/web-starter-app/db"
	"github.com/jackc/web-starter-app/lib/bee"
	"github.com/jackc/web-starter-app/view"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/shopspring/decimal"
)

// NewHandler returns an http.Handler that serves the web application.
func NewHandler(
	dbpool *pgxpool.Pool,
	logger *zerolog.Logger,
	csrfKey []byte,
	secureCookies bool,
	cookieAuthenticationKey []byte,
	cookieEncryptionKey []byte,
	assetManifest map[string]string,
) (http.Handler, error) {

	router := chi.NewRouter()

	env := &environment{
		dbpool:       dbpool,
		logger:       logger,
		secureCookie: securecookie.New(cookieAuthenticationKey, cookieEncryptionKey),
		sessionCookieTemplate: &http.Cookie{
			Name:     "web-starter-app-session",
			Path:     "/",
			Secure:   secureCookies,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
	}

	router.Use(middleware.Compress(5))
	router.Use(middleware.RealIP)

	router.Use(hlog.NewHandler(*logger))
	router.Use(hlog.RequestIDHandler("request_id", "x-request-id"))
	router.Use(hlog.MethodHandler("method"))
	router.Use(hlog.URLHandler("url"))
	router.Use(hlog.RemoteAddrHandler("remote_ip"))
	router.Use(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Info().
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Msg("HTTP request")
	}))

	router.Use(middleware.Recoverer)

	router.Use(setContextValue(ctxKeyEnvironment, env))

	viewEnvironment := &view.Environment{
		AssetManifest: assetManifest,
	}
	if assetManifest == nil {
		viewEnvironment.ViteHotReload = true
	}
	router.Use(setContextValue(view.EnvironmentCtxKey, viewEnvironment))

	CSRF := csrf.Protect(csrfKey, csrf.Path("/"), csrf.Secure(secureCookies))
	router.Use(CSRF)

	router.Use(loginSessionHandler())

	hb := bee.HandlerBuilder[*environment]{
		CtxKeyEnv: ctxKeyEnvironment,
		ErrorHandlers: []bee.ErrorHandler{
			func(w http.ResponseWriter, r *http.Request, err error) (bool, error) {
				zerolog.Ctx(r.Context()).Error().Err(err).Msg("error handling request")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return true, nil
			},
		},
	}

	router.Method("GET", "/login", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
		return view.ApplicationLayout(view.LoginPage(nil)).Render(ctx, w)
	}))

	router.Method("POST", "/login/submit", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
		user, err := db.GetUserByUsername(ctx, env.dbpool, r.FormValue("username"))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				loginErrors := &errortree.Node{}
				loginErrors.Add(nil, errors.New("Invalid username or password"))
				return view.ApplicationLayout(view.LoginPage(loginErrors)).Render(ctx, w)
			}
			return err
		}

		err = db.ValidateUserPassword(ctx, env.dbpool, user.ID, r.FormValue("password"))
		if err != nil {
			loginErrors := &errortree.Node{}
			loginErrors.Add(nil, errors.New("Invalid username or password"))
			return view.ApplicationLayout(view.LoginPage(loginErrors)).Render(ctx, w)
		}

		now := time.Now()
		loginSessionID, err := pgxutil.InsertRowReturning(ctx, env.dbpool, "login_sessions", map[string]any{
			"id":                            uuid.Must(uuid.NewV7()),
			"user_id":                       user.ID,
			"user_agent":                    zeronull.Text(r.UserAgent()),
			"login_time":                    now,
			"login_request_id":              middleware.GetReqID(ctx),
			"approximate_last_request_time": now,
		},
			"id",
			pgx.RowTo[uuid.UUID],
		)
		if err != nil {
			return err
		}

		setLoginSessionCookie(w, r, loginSessionID)

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return nil
	}))

	router.Method("POST", "/logout", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
		loginSession := getLoginSession(ctx)
		if loginSession != nil {
			_, err := env.dbpool.Exec(ctx, "delete from login_sessions where id=$1", loginSession.ID)
			if err != nil {
				return err
			}
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil
	}))

	router.Group(func(router chi.Router) {
		router.Use(requireCurrentUserHandler("/login"))
		router.Method("GET", "/", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
			now, err := db.GetCurrentTime(ctx, env.dbpool)
			if err != nil {
				return err
			}

			loginSession := getLoginSession(ctx)
			name := loginSession.User.Username

			var walkRecords []*view.HomeWalkRecord
			if loginSession.User != nil {
				walkRecords, err = pgxutil.Select(ctx, env.dbpool, "select id, duration, distance_in_miles, finish_time from walks where user_id=$1 order by finish_time desc", []any{loginSession.User.ID}, pgx.RowToAddrOfStructByPos[view.HomeWalkRecord])
				if err != nil {
					return err
				}
			}

			return view.ApplicationLayout(view.Home(name, now, walkRecords)).Render(r.Context(), w)
		}))

		router.Method("GET", "/walks/new", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
			formData := view.WalkFormFields{}
			return view.ApplicationLayout(view.WalksNew(&formData, nil)).Render(r.Context(), w)
		}))

		router.Method("POST", "/walks", func() http.Handler {
			return hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
				loginSession := getLoginSession(ctx)

				formData := view.WalkFormFields{}
				err := structify.Parse(params, &formData)
				if err != nil {
					return err
				}

				validationErrors := &errortree.Node{}
				duration, err := time.ParseDuration(formData.Duration)
				if err != nil {
					validationErrors.Add([]any{"duration"}, errors.New("Invalid duration"))
				} else if duration <= 0 {
					validationErrors.Add([]any{"duration"}, errors.New("Duration must be greater than 0"))
				}

				distanceInMiles, err := decimal.NewFromString(formData.DistanceInMiles)
				if err != nil {
					validationErrors.Add([]any{"distanceInMiles"}, errors.New("Invalid distance"))
				} else if distanceInMiles.LessThanOrEqual(decimal.Zero) {
					validationErrors.Add([]any{"distanceInMiles"}, errors.New("Distance must be greater than 0"))
				}

				if validationErrors.AllErrors() != nil {
					return view.ApplicationLayout(view.WalksNew(&formData, validationErrors)).Render(r.Context(), w)
				}

				err = pgxutil.InsertRow(ctx, env.dbpool, "walks", map[string]any{
					"id":                uuid.Must(uuid.NewV7()),
					"user_id":           loginSession.User.ID,
					"duration":          formData.Duration,
					"distance_in_miles": formData.DistanceInMiles,
				})
				if err != nil {
					return err
				}

				http.Redirect(w, r, "/", http.StatusSeeOther)
				return nil
			})
		}())

		router.Method("GET", "/walks/{id}", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
			loginSession := getLoginSession(ctx)

			walkID, err := uuid.FromString(params["id"].(string))
			if err != nil {
				return err
			}
			walkRecord, err := pgxutil.SelectRow(ctx, env.dbpool, "select id, duration, distance_in_miles, finish_time from walks where id = $1 and user_id = $2", []any{walkID, loginSession.User.ID}, pgx.RowToAddrOfStructByPos[view.WalkRecord])
			if err != nil {
				return err
			}

			return view.ApplicationLayout(view.WalksShow(walkRecord)).Render(r.Context(), w)
		}))

		router.Method("GET", "/walks/{id}/edit", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
			loginSession := getLoginSession(ctx)

			walkID, err := uuid.FromString(params["id"].(string))
			if err != nil {
				return err
			}

			var duration time.Duration
			var distanceInMiles decimal.Decimal
			err = env.dbpool.QueryRow(
				ctx,
				"select duration, distance_in_miles from walks where id = $1 and user_id = $2",
				walkID, loginSession.User.ID,
			).Scan(&duration, &distanceInMiles)
			if err != nil {
				return err
			}

			formData := view.WalkFormFields{
				Duration:        duration.String(),
				DistanceInMiles: distanceInMiles.String(),
			}
			return view.ApplicationLayout(view.WalksEdit(walkID, &formData, nil)).Render(r.Context(), w)
		}))

		router.Method("POST", "/walks/{id}/update", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
			loginSession := getLoginSession(ctx)

			walkID, err := uuid.FromString(params["id"].(string))
			if err != nil {
				return err
			}

			formData := view.WalkFormFields{}
			err = structify.Parse(params, &formData)
			if err != nil {
				if validationErrors, ok := err.(*errortree.Node); ok {
					return view.ApplicationLayout(view.WalksEdit(walkID, &formData, validationErrors)).Render(r.Context(), w)
				}
				return err
			}

			validationErrors := &errortree.Node{}
			duration, err := time.ParseDuration(formData.Duration)
			if err != nil {
				validationErrors.Add([]any{"duration"}, errors.New("Invalid duration"))
			} else if duration <= 0 {
				validationErrors.Add([]any{"duration"}, errors.New("Duration must be greater than 0"))
			}

			distanceInMiles, err := decimal.NewFromString(formData.DistanceInMiles)
			if err != nil {
				validationErrors.Add([]any{"distanceInMiles"}, errors.New("Invalid distance"))
			} else if distanceInMiles.LessThanOrEqual(decimal.Zero) {
				validationErrors.Add([]any{"distanceInMiles"}, errors.New("Distance must be greater than 0"))
			}

			if validationErrors.AllErrors() != nil {
				return view.ApplicationLayout(view.WalksEdit(walkID, &formData, validationErrors)).Render(r.Context(), w)
			}

			err = pgxutil.UpdateRow(ctx, env.dbpool, "walks", map[string]any{
				"duration":          duration,
				"distance_in_miles": distanceInMiles,
			}, map[string]any{
				"id":      walkID,
				"user_id": loginSession.User.ID,
			})
			if err != nil {
				return err
			}

			http.Redirect(w, r, "/", http.StatusSeeOther)
			return nil
		}))

		router.Method("POST", "/walks/{id}/delete", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
			loginSession := getLoginSession(ctx)

			walkID, err := uuid.FromString(params["id"].(string))
			if err != nil {
				return err
			}

			_, err = pgxutil.ExecRow(ctx, env.dbpool, "delete from walks where id = $1 and user_id = $2", walkID, loginSession.User.ID)
			if err != nil {
				return err
			}

			http.Redirect(w, r, "/", http.StatusSeeOther)
			return nil
		}))

		router.Method("GET", "/change_password", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
			formData := view.ChangePasswordFormFields{}

			return view.ApplicationLayout(view.ChangePassword(&formData, nil)).Render(r.Context(), w)
		}))

		router.Method("POST", "/change_password", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
			loginSession := getLoginSession(ctx)

			formData := view.ChangePasswordFormFields{}
			err := structify.Parse(params, &formData)
			if err != nil {
				if validationErrors, ok := err.(*errortree.Node); ok {
					return view.ApplicationLayout(view.ChangePassword(&formData, validationErrors)).Render(r.Context(), w)
				}
				return err
			}

			err = db.ValidateUserPassword(ctx, env.dbpool, loginSession.User.ID, formData.CurrentPassword)
			if err != nil {
				validationErrors := &errortree.Node{}
				validationErrors.Add([]any{"currentPassword"}, errors.New("Invalid password"))
				return view.ApplicationLayout(view.ChangePassword(&formData, validationErrors)).Render(r.Context(), w)
			}

			err = db.SetUserPassword(ctx, env.dbpool, loginSession.User.ID, formData.NewPassword)
			if err != nil {
				return err
			}

			http.Redirect(w, r, "/", http.StatusSeeOther)
			return nil
		}))
	})

	router.Route("/system", func(router chi.Router) {
		router.Use(requireSystemUserHandler("/login"))

		router.Method("GET", "/users", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
			users, err := pgxutil.Select(ctx, env.dbpool, "select id, username, system from users order by username", nil, pgx.RowToStructByPos[view.SystemUsersPageUser])
			if err != nil {
				return err
			}

			return view.ApplicationLayout(view.SystemUsersPage(users)).Render(r.Context(), w)
		}))

		router.Method("GET", "/users/new", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
			formData := view.SystemUsersFormFields{}
			return view.ApplicationLayout(view.SystemUsersNewPage(&formData, nil)).Render(r.Context(), w)
		}))

		router.Method("POST", "/users", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
			formData := view.SystemUsersFormFields{}
			err := structify.Parse(params, &formData)
			if err != nil {
				if validationErrors, ok := err.(*errortree.Node); ok {
					return view.ApplicationLayout(view.SystemUsersNewPage(&formData, validationErrors)).Render(r.Context(), w)
				}
				return err
			}

			userID := uuid.Must(uuid.NewV7())

			var nameTaken bool
			err = env.dbpool.QueryRow(ctx, "select exists(select 1 from users where username = $1)", formData.Username).Scan(&nameTaken)
			if err != nil {
				return err
			}
			if nameTaken {
				validationErrors := &errortree.Node{}
				validationErrors.Add([]any{"username"}, errors.New("Username is already taken"))
				return view.ApplicationLayout(view.SystemUsersNewPage(&formData, validationErrors)).Render(r.Context(), w)
			}

			err = pgxutil.InsertRow(ctx, env.dbpool, "users", map[string]any{
				"id":       userID,
				"username": formData.Username,
				"system":   formData.System,
			})
			if err != nil {
				return err
			}

			http.Redirect(w, r, "/system/users", http.StatusSeeOther)
			return nil

		}))

		router.Method("GET", "/users/{id}", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
			userID, err := uuid.FromString(params["id"].(string))
			if err != nil {
				return err
			}
			user, err := pgxutil.SelectRow(ctx, env.dbpool, "select id, username, system from users where id = $1", []any{userID}, pgx.RowToAddrOfStructByPos[view.SystemUsersPageUser])
			if err != nil {
				return err
			}

			return view.ApplicationLayout(view.SystemUsersShowPage(user)).Render(r.Context(), w)
		}))

		router.Method("GET", "/users/{id}/edit", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
			userID, err := uuid.FromString(params["id"].(string))
			if err != nil {
				return err
			}

			formData := view.SystemUsersFormFields{}
			err = env.dbpool.QueryRow(ctx, "select username, system from users where id = $1", userID).Scan(&formData.Username, &formData.System)
			if err != nil {
				return err
			}

			return view.ApplicationLayout(view.SystemUsersEditPage(userID, &formData, nil)).Render(r.Context(), w)
		}))

		router.Method("POST", "/users/{id}/update", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
			userID, err := uuid.FromString(params["id"].(string))
			if err != nil {
				return err
			}

			formData := view.SystemUsersFormFields{}
			err = structify.Parse(params, &formData)
			if err != nil {
				if validationErrors, ok := err.(*errortree.Node); ok {
					return view.ApplicationLayout(view.SystemUsersEditPage(userID, &formData, validationErrors)).Render(r.Context(), w)
				}
				return err
			}

			var nameTaken bool
			err = env.dbpool.QueryRow(ctx, "select exists(select 1 from users where username = $1 and id <> $2)", formData.Username, userID).Scan(&nameTaken)
			if err != nil {
				return err
			}
			if nameTaken {
				validationErrors := &errortree.Node{}
				validationErrors.Add([]any{"username"}, errors.New("Username is already taken"))
				return view.ApplicationLayout(view.SystemUsersEditPage(userID, &formData, validationErrors)).Render(r.Context(), w)
			}

			err = pgxutil.UpdateRow(ctx, env.dbpool, "users", map[string]any{
				"username": formData.Username,
				"system":   formData.System,
			}, map[string]any{
				"id": userID,
			})
			if err != nil {
				return err
			}

			// TODO handle validation errors

			http.Redirect(w, r, "/system/users", http.StatusSeeOther)
			return nil
		}))

		router.Method("POST", "/users/{id}/delete", hb.New(func(ctx context.Context, w http.ResponseWriter, r *http.Request, env *environment, params map[string]any) error {
			userID, err := uuid.FromString(params["id"].(string))
			if err != nil {
				return err
			}

			_, err = pgxutil.ExecRow(ctx, env.dbpool, "delete from users where id = $1", userID)
			if err != nil {
				return err
			}

			http.Redirect(w, r, "/system/users", http.StatusSeeOther)
			return nil
		}))
	})

	return router, nil
}

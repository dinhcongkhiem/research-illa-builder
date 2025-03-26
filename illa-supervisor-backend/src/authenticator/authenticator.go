package authenticator

import (
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"time"
	"log"
	"strings"
	"context"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"

	"github.com/illacloud/illa-supervisor-backend/src/model"
	"github.com/illacloud/illa-supervisor-backend/src/utils/config"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

)

type KeycloakValidator struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	config   *oauth2.Config
}

type AuthClaims struct {
	User   int       `json:"user"`
	UUID   uuid.UUID `json:"uuid"`
	Random string    `json:"rnd"`
	jwt.RegisteredClaims
}

type Authenticator struct {
	Storage *model.Storage
	Cache   *model.Cache
	KeycloakValidator *KeycloakValidator
}

func NewKeycloakValidator(
    ctx context.Context, 
    issuerURL string,
    clientID string,
    clientSecret string,
) (*KeycloakValidator, error) {
    // Initialize the OIDC provider
    provider, err := oidc.NewProvider(ctx, issuerURL)
    if err != nil {
        log.Printf("[ERROR] Failed to initialize OIDC provider: %v", err)
        return nil, fmt.Errorf("failed to initialize OIDC provider: %w", err)
    }
    
    // Configure the OAuth2 config
    config := &oauth2.Config{
        ClientID:     clientID,
        ClientSecret: clientSecret,
        Endpoint:     provider.Endpoint(),
        RedirectURL:  "",
        Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
    }
    
    verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
    
    return &KeycloakValidator{
        provider: provider,
        verifier: verifier,
        config:   config,
    }, nil
}
func NewAuthenticator(storage *model.Storage, cache *model.Cache) *Authenticator {
    // Initialize Keycloak validator
    ctx := context.Background()
    conf := config.GetInstance()
    
    var keycloakValidator *KeycloakValidator
    
    if conf.GetKeycloakIssuerURL() != "" && conf.GetKeycloakClientID() != "" {
        var err error
        keycloakValidator, err = NewKeycloakValidator(
            ctx, 
            conf.GetKeycloakIssuerURL(),
            conf.GetKeycloakClientID(),
            conf.GetKeycloakClientSecret(),
        )
        
        if err != nil {
            log.Printf("[WARN] Failed to initialize KeycloakValidator: %v", err)
        } else {
            log.Printf("[INFO] Successfully initialized Keycloak validator with issuer: %s", conf.GetKeycloakIssuerURL())
        }
    } else {
        log.Printf("[INFO] Keycloak configuration not provided, SSO disabled")
    }
    
    a := &Authenticator{
        Storage: storage,
        Cache:   cache,
        KeycloakValidator: keycloakValidator,
    }
    return a
}

func (a *Authenticator) ValidateAccessToken(accessToken string) (bool, error) {
	_, _, err := ExtractUserIDFromToken(accessToken)
	if err != nil {
		return false, err
	}
	return true, nil
}

func ExtractUserIDFromToken(accessToken string) (int, uuid.UUID, error) {
	authClaims := &AuthClaims{}
	token, err := jwt.ParseWithClaims(accessToken, authClaims, func(token *jwt.Token) (interface{}, error) {
		conf := config.GetInstance()
		return []byte(conf.GetSecretKey()), nil
	})
	if err != nil {
		return 0, uuid.Nil, err
	}

	claims, ok := token.Claims.(*AuthClaims)
	if !(ok && token.Valid) {
		return 0, uuid.Nil, err
	}

	return claims.User, claims.UUID, nil
}

func ExtractExpiresAtFromToken(accessToken string) (*jwt.NumericDate, error) {
	authClaims := &AuthClaims{}
	token, err := jwt.ParseWithClaims(accessToken, authClaims, func(token *jwt.Token) (interface{}, error) {
		conf := config.GetInstance()
		return []byte(conf.GetSecretKey()), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*AuthClaims)
	if !(ok && token.Valid) {
		return nil, err
	}

	return claims.ExpiresAt, nil
}

func (a *Authenticator) ValidateUser(user *model.User, id int, uid uuid.UUID) (bool, error) {
	// refuse invalied user
	emptyUUID, _ := uuid.Parse("00000000-0000-0000-0000-000000000000")
	if id == 0 || uid == emptyUUID {
		return false, errors.New("invalied user ID or UID.")
	}
	if user.ID != id || user.UID != uid {
		return false, errors.New("no such user")
	}

	return true, nil
}

func CreateAccessToken(id int, uid uuid.UUID) (string, error) {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	vCode := fmt.Sprintf("%06v", rnd.Int31n(10000))

	claims := &AuthClaims{
		User:   id,
		UUID:   uid,
		Random: vCode,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "ILLA",
			ExpiresAt: &jwt.NumericDate{
				Time: time.Now().Add(time.Hour * 24 * 7),
			},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	conf := config.GetInstance()
	accessToken, err := token.SignedString([]byte(conf.GetSecretKey()))
	if err != nil {
		return "", err
	}
	return accessToken, nil
}

func (a *Authenticator) JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken := c.Request.Header["Authorization"]
		var token string
		if len(accessToken) != 1 {
			log.Printf("[ERROR] JWTAuth - Invalid Authorization header length: %d", len(accessToken))
			c.AbortWithStatus(http.StatusUnauthorized)
		} else {
			token = accessToken[0]
			log.Printf("[INFO] JWTAuth - Received token: %s", token)
		}

		isKeycloakToken := strings.HasPrefix(token, "Bearer ")

		if isKeycloakToken {
            if a.KeycloakValidator == nil {
                log.Printf("[ERROR] JWTAuth - KeycloakValidator is not initialized")
                c.AbortWithStatus(http.StatusInternalServerError)
                return
            }
            
            idToken, err := a.KeycloakValidator.ValidateToken(c, token)
            if err != nil {
                log.Printf("[ERROR] JWTAuth - Failed to validate Keycloak token: %v", err)
                c.AbortWithStatus(http.StatusUnauthorized)
                return
            }
            
            var claims struct {
                Email         string `json:"email"`
                PreferredName string `json:"preferred_username"`
                Name          string `json:"name"`
                Sub           string `json:"sub"`
            }
            if err := idToken.Claims(&claims); err != nil {
                log.Printf("[ERROR] JWTAuth - Failed to extract claims: %v", err)
                c.AbortWithStatus(http.StatusUnauthorized)
                return
            }
            
            user, err := a.Storage.UserStorage.RetrieveByEmail(claims.Email)
            if err != nil {
                newUser := model.User{
                    Email:    claims.Email,
                    Nickname: claims.Name,
                    UID:      uuid.New(), 
					SSOConfig: "{}",
					Customization: "{}",
                }
                
                userID, err := a.Storage.UserStorage.Create(&newUser)
                if err != nil {
                    log.Printf("[ERROR] JWTAuth - Failed to create new user: %v", err)
                    c.AbortWithStatus(http.StatusInternalServerError)
                    return
                }
                
                user, err = a.Storage.UserStorage.RetrieveByID(userID)
                if err != nil {
                    log.Printf("[ERROR] JWTAuth - Failed to retrieve newly created user: %v", err)
                    c.AbortWithStatus(http.StatusInternalServerError)
                    return
                }
				team, err := a.Storage.TeamStorage.RetrieveByUID("00000000-0000-0000-0000-000000000000")

				if err != nil {
					log.Printf("[ERROR] JWTAuth - Failed to retrieve team: %v", err)
					c.AbortWithStatus(http.StatusInternalServerError)
					return
				}

				_, err = a.Storage.TeamMemberStorage.Create(&model.TeamMember{
					TeamID: team.ID,
					UserID: user.ID,
					UserRole: 1,
					Status: 1,
					Permission: `{"Config": 0}`,
				})

				if err != nil {
					log.Printf("[ERROR] JWTAuth - Failed to create team member for user %s: %v", user.Email, err)
					c.AbortWithStatus(http.StatusInternalServerError)
					return
				}
            }
            
            c.Set("userID", user.ID)
            log.Printf("[INFO] JWTAuth - Successfully authenticated Keycloak user: %s (ID: %d)", claims.Email, user.ID)
		} else {
			userID, userUID, extractErr := ExtractUserIDFromToken(token)
			if extractErr != nil {
				log.Printf("[ERROR] JWTAuth - Failed to extract user info from token: %v", extractErr)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			log.Printf("[INFO] JWTAuth - Extracted userID: %d, userUID: %s", userID, userUID)
	
			user, err := a.Storage.UserStorage.RetrieveByIDAndUID(userID, userUID)
			if err != nil {
				log.Printf("[ERROR] JWTAuth - Failed to retrieve user from storage: %v", err)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			log.Printf("[INFO] JWTAuth - Successfully retrieved user: %+v", user)
	
			// validate
			validAccessToken, validaAccessErr := a.ValidateAccessToken(token)
			log.Printf("[INFO] JWTAuth - Token validation result: valid=%v, error=%v", validAccessToken, validaAccessErr)
	
			validUser, validUserErr := a.ValidateUser(user, userID, userUID)
			log.Printf("[INFO] JWTAuth - User validation result: valid=%v, error=%v", validUser, validUserErr)
	
			expireAtAvaliable, errInValidatteExpireAt := a.DoesAccessTokenExpiredAtAvaliable(user, token)
			log.Printf("[INFO] JWTAuth - Token expiration validation: valid=%v, error=%v", expireAtAvaliable, errInValidatteExpireAt)
	
			if validAccessToken && validUser && expireAtAvaliable && validaAccessErr == nil && extractErr == nil && validUserErr == nil && errInValidatteExpireAt == nil {
				log.Printf("[INFO] JWTAuth - Authentication successful for userID: %d", userID)
				c.Set("userID", userID)
			} else {
				log.Printf("[ERROR] JWTAuth - Authentication failed. validAccessToken=%v, validUser=%v, expireAtAvaliable=%v, validaAccessErr=%v, extractErr=%v, validUserErr=%v, errInValidatteExpireAt=%v",
					validAccessToken, validUser, expireAtAvaliable, validaAccessErr, extractErr, validUserErr, errInValidatteExpireAt)
				c.AbortWithStatus(http.StatusUnauthorized)
			}
		}
		c.Next()
	}
}

func (a *Authenticator) ManualAuth(accessToken string) (bool, error) {
	log.Printf("[INFO] ManualAuth - Starting manual authentication with token: %s", accessToken)
	// fetch user

	isBearerToken := strings.HasPrefix(accessToken, "Bearer ")
    
    if isBearerToken && a.KeycloakValidator != nil {
        log.Printf("[INFO] ManualAuth - Processing as Keycloak token")
        idToken, err := a.KeycloakValidator.ValidateToken(context.Background(), accessToken)
        if err != nil {
            log.Printf("[ERROR] ManualAuth - Failed to validate Keycloak token: %v", err)
            return false, errors.New("auth failed: invalid Keycloak token")
        }
        
        var claims struct {
            Email         string `json:"email"`
            PreferredName string `json:"preferred_username"`
            Name          string `json:"name"`
            Sub           string `json:"sub"`
        }
        if err := idToken.Claims(&claims); err != nil {
            log.Printf("[ERROR] ManualAuth - Failed to extract claims: %v", err)
            return false, errors.New("auth failed: invalid token claims")
        }
        user, err := a.Storage.UserStorage.RetrieveByEmail(claims.Email)
        if err != nil {
            log.Printf("[ERROR] ManualAuth - User not found for email %s: %v", claims.Email, err)
            return false, errors.New("auth failed: user not found")
        }
        
        log.Printf("[INFO] ManualAuth - Successfully authenticated Keycloak user: %s (ID: %d)", claims.Email, user.ID)
        return true, nil
	}
	userID, userUID, extractErr := ExtractUserIDFromToken(accessToken)
	log.Printf("[INFO] ManualAuth - Extracted userID: %d, userUID: %s, error: %v", userID, userUID, extractErr)

	user, err := a.Storage.UserStorage.RetrieveByIDAndUID(userID, userUID)
	if err != nil {
		log.Printf("[ERROR] ManualAuth - Failed to retrieve user: %v", err)
		return false, errors.New("auth failed.")
	}
	log.Printf("[INFO] ManualAuth - Successfully retrieved user: %+v", user)

	validAccessToken, validaAccessErr := a.ValidateAccessToken(accessToken)
	log.Printf("[INFO] ManualAuth - Token validation result: valid=%v, error=%v", validAccessToken, validaAccessErr)

	validUser, validUserErr := a.ValidateUser(user, userID, userUID)
	log.Printf("[INFO] ManualAuth - User validation result: valid=%v, error=%v", validUser, validUserErr)

	expireAtAvaliable, errInValidatteExpireAt := a.DoesAccessTokenExpiredAtAvaliable(user, accessToken)
	log.Printf("[INFO] ManualAuth - Token expiration validation: valid=%v, error=%v", expireAtAvaliable, errInValidatteExpireAt)

	if validAccessToken && validUser && expireAtAvaliable && validaAccessErr == nil && extractErr == nil && validUserErr == nil && errInValidatteExpireAt == nil {
		log.Printf("[INFO] ManualAuth - Authentication successful for userID: %d", userID)
		return true, nil
	} else {
		log.Printf("[ERROR] ManualAuth - Authentication failed. validAccessToken=%v, validUser=%v, expireAtAvaliable=%v, validaAccessErr=%v, extractErr=%v, validUserErr=%v, errInValidatteExpireAt=%v",
			validAccessToken, validUser, expireAtAvaliable, validaAccessErr, extractErr, validUserErr, errInValidatteExpireAt)
		return false, errors.New("auth failed.")
	}
}

func ExtractExpiresAtFromTokenInString(accessToken string) (string, error) {
	// extract now token expiresAt
	expireDate, errInExtract := ExtractExpiresAtFromToken(accessToken)
	if errInExtract != nil {
		return "", errInExtract
	}
	expiresAt := strconv.FormatInt(expireDate.UTC().Unix(), 10)
	return expiresAt, nil
}

// for logout case
func (a *Authenticator) DoesAccessTokenExpiredAtAvaliable(user *model.User, accessToken string) (bool, error) {
	// extract now token expiresAt
	expireDate, errInExtract := ExtractExpiresAtFromToken(accessToken)
	if errInExtract != nil {
		return false, errInExtract
	}
	expiresAt := strconv.FormatInt(expireDate.UTC().Unix(), 10)
	// get history data
	return a.Cache.JWTCache.DoesUserJWTTokenAvaliable(user, expiresAt)
}

func (kv *KeycloakValidator) ValidateToken(
	ctx context.Context, 
	tokenString string,
) (*oidc.IDToken, error) {
	// Loại bỏ tiền tố "Bearer " nếu có
	if strings.HasPrefix(tokenString, "Bearer ") {
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	}

	// Xác thực token
	idToken, err := kv.verifier.Verify(ctx, tokenString)
	if err != nil {
		log.Printf("[ERROR] Failed to verify token: %v", err)
		return nil, errors.New("invalid token")
	}

	return idToken, nil
}


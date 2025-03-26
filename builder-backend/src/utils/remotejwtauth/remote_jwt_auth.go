package remotejwtauth

import (
	"fmt"
	"log"
	"encoding/json"
	"net/http"
	"strings"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/illacloud/builder-backend/src/utils/config"
	"github.com/illacloud/builder-backend/src/utils/supervisor"
)

type AuthClaims struct {
	User   int       `json:"user"`
	UUID   uuid.UUID `json:"uuid"`
	Random string    `json:"rnd"`
	jwt.RegisteredClaims
}

func RemoteJWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// fetch content
		accessToken := c.Request.Header["Authorization"]
		var token string
		if len(accessToken) != 1 {
			c.AbortWithStatus(http.StatusUnauthorized)
		} else {
			token = accessToken[0]
		}

		sv := supervisor.NewSupervisor()

		validated, errInValidate := sv.ValidateUserAccount(token)
		fmt.Printf("token: %v\n", token)
		if errInValidate != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			c.Next()
		}
		if !validated {
			c.AbortWithStatus(http.StatusUnauthorized)
			c.Next()
		}
		// ok set userID
		userID, userUID, errInExtractUserID := ExtractUserIDFromToken(token)
		if errInExtractUserID != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			c.Next()
		}
		log.Printf("userID: %v\n", userID)
		log.Printf("userUID: %v\n", userUID)

		c.Set("userID", userID)
		c.Set("userUID", userUID)
		c.Next()
	}
}

func ExtractUserIDFromToken(accessToken string) (int, uuid.UUID, error) {

	authClaims := &AuthClaims{}
	isKeycloakToken := strings.HasPrefix(accessToken, "Bearer ")
	var token *jwt.Token
	var err error

	if isKeycloakToken {
		email, err := ExtractEmailFromToken(accessToken)
		sv := supervisor.NewSupervisor()
		userDataJSON, err := sv.GetUserByEmail(email)
		if err != nil {
			log.Printf("[ERROR] Failed to get user by email: %v", err)
			return 0, uuid.Nil, err
		}
		log.Printf("userDataJSON: %v\n", userDataJSON)
		var userData struct {
			UserID   int       `json:"userID"`
			UserUUID uuid.UUID `json:"userUUID"`
		}
		
		if err := json.Unmarshal([]byte(userDataJSON), &userData); err != nil {
			log.Printf("[ERROR] Failed to parse user data: %v", err)
			return 0, uuid.Nil, err
		}
		log.Printf("userData: %v\n", userData)
		return userData.UserID, userData.UserUUID, nil
	}else {
		token, err = jwt.ParseWithClaims(accessToken, authClaims, func(token *jwt.Token) (interface{}, error) {
			conf := config.GetInstance()
			return []byte(conf.GetSecretKey()), nil
		})
	}
	if err != nil {
		return 0, uuid.Nil, err
	}

	claims, ok := token.Claims.(*AuthClaims)
	if !(ok && token.Valid) {
		return 0, uuid.Nil, err
	}
	return claims.User, claims.UUID, nil
}


func ExtractEmailFromToken(accessToken string) (string, error) {
	accessToken = strings.TrimPrefix(accessToken, "Bearer ")
	token, _, err := new(jwt.Parser).ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("invalid token: %v", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}
	email, ok := claims["email"].(string)
	if !ok {
		return "", fmt.Errorf("email not found in token")
	}
	return email, nil
}

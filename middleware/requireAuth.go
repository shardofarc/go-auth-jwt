package middleware

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/shardofarc/go-auth-jwt/initializers"
	"github.com/shardofarc/go-auth-jwt/models"
)

func RequireAuth(c *gin.Context) {
	accessToken, err := c.Cookie("Authorization")
	refreshToken, err2 := c.Cookie("Refresh")

	if err != nil || accessToken == "" || err2 != nil || refreshToken == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("KEY")), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}))

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		var user models.User
		initializers.DB.First(&user, claims["sub"])

		if user.ID == 0 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if c.ClientIP() != claims["uip"] {
		}

		c.Set("user", user)
		c.Set("userAgent", claims["age"])

		c.Next()
	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
}

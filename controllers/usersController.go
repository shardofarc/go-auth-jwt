package controllers

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/beevik/guid"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/shardofarc/go-auth-jwt/initializers"
	"github.com/shardofarc/go-auth-jwt/models"
)

func CreateUser(c *gin.Context) {
	var userGuid = guid.New().String()
	user := models.User{UserGuid: userGuid}

	fmt.Println(user)

	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})

		return
	}

	c.JSON(http.StatusOK, user)
}

func GetUsers(c *gin.Context) {
	var users models.User
	result := initializers.DB.Find(&users)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to find users",
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}

func GenerateTokens(c *gin.Context) {
	var body struct {
		UserGuid string
	}

	if c.ShouldBindBodyWithJSON(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
	}

	fmt.Println("guid: " + body.UserGuid)
	var user models.User
	initializers.DB.First(&user, "user_guid = ?", body.UserGuid)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to find user",
		})

		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Minute * 5).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("KEY")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access": tokenString,
	})
}

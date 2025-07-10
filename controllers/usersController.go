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
	"golang.org/x/crypto/bcrypt"
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

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.ID,
		"num": user.UserGuid,
		"exp": time.Now().Add(time.Minute).Unix(),
	})

	accessString, err := accessToken.SignedString([]byte(os.Getenv("KEY")))
	refreshString := time.Now().Add(time.Hour).Format("2006/01/02 03:04")

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})

		return
	}

	refreshHash, err := bcrypt.GenerateFromPassword([]byte(refreshString), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create tokens",
		})

		return
	}

	user.Refresh = string(refreshHash)
	result := initializers.DB.Save(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to save refresh",
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access":  accessString,
		"refresh": refreshString,
	})
}

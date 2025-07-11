package controllers

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
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

func GetGuid(c *gin.Context) {
	user := c.MustGet("user").(models.User)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"guid":    user.UserGuid,
		"message": c.Request.UserAgent(),
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

	accessToken, refreshToken, err := createTokens(user, c)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create tokens",
		})
		return
	}

	encodedRefresh := base64.StdEncoding.EncodeToString([]byte(refreshToken))

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", accessToken, 3600, "", "", true, true)
	c.SetCookie("Refresh", encodedRefresh, 3600, "", "", true, true)

	c.JSON(http.StatusOK, gin.H{})
}

func Refresh(c *gin.Context) {
	accessToken, err := c.Cookie("Authorization")
	encodedRefresh, err2 := c.Cookie("Refresh")

	if err != nil || accessToken == "" || err2 != nil || encodedRefresh == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to find tokens",
		})
		return
	}

	refreshTokenBytes, err := base64.StdEncoding.DecodeString(encodedRefresh)
	refreshToken := string(refreshTokenBytes)
	user := c.MustGet("user").(models.User)
	accessUserAgent := c.MustGet("userAgent").(string)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid refresh token",
		})
		return
	}

	if strings.Compare(refreshToken, accessToken[strings.LastIndexByte(accessToken, '.'):strings.LastIndexByte(accessToken, '.')+72]) != 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid pair of tokens",
		})
		return
	}

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user",
		})
		return
	}

	if strings.Compare(accessUserAgent, c.Request.UserAgent()) != 0 {
		deauth(c)

		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid userAgent",
		})
		return
	}

	fmt.Println("here")

	err = bcrypt.CompareHashAndPassword([]byte(user.Refresh), []byte(refreshToken))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid refresh token",
		})
		return
	}

	newAccessToken, newRefreshToken, err := createTokens(user, c)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create tokens",
		})
		return
	}

	encodedNewRefresh := base64.StdEncoding.EncodeToString([]byte(newRefreshToken))

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", newAccessToken, 3600, "", "", true, true)
	c.SetCookie("Refresh", encodedNewRefresh, 3600, "", "", true, true)

	c.JSON(http.StatusOK, gin.H{})
}

func Deauthorize(c *gin.Context) {
	deauth(c)

	c.JSON(http.StatusOK, gin.H{})
}

func createTokens(user models.User, c *gin.Context) (string, string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.ID,
		"num": user.UserGuid,
		"age": c.Request.UserAgent(),
		"uip": c.ClientIP(),
		"exp": time.Now().Add(time.Minute).Unix(),
	})

	accessString, err := accessToken.SignedString([]byte(os.Getenv("KEY")))
	refreshString := accessString[strings.LastIndexByte(accessString, '.') : strings.LastIndexByte(accessString, '.')+72]

	if err != nil {
		return "", "", err
	}

	refreshHash, err := bcrypt.GenerateFromPassword([]byte(refreshString), 10)

	if err != nil {
		return "", "", err
	}

	user.Refresh = string(refreshHash)
	result := initializers.DB.Save(&user)

	if result.Error != nil {
		return "", "", err
	}

	return accessString, refreshString, nil
}

func deauth(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", "", 0, "", "", true, true)
}

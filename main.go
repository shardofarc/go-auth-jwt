package main

import (
	"github.com/gin-gonic/gin"
	"github.com/shardofarc/go-auth-jwt/controllers"
	"github.com/shardofarc/go-auth-jwt/initializers"
	"github.com/shardofarc/go-auth-jwt/middleware"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()

	r.POST("/createUser", controllers.CreateUser)
	r.GET("/getUsers", controllers.GetUsers)
	r.POST("/setWebhookForUser", controllers.SetWebhook)
	r.GET("/generateTokens", controllers.GenerateTokens)
	r.GET("/refresh", middleware.RequireAuth, controllers.Refresh)
	r.GET("/getGuid", middleware.RequireAuth, controllers.GetGuid)
	r.GET("/deauthorize", controllers.Deauthorize)

	r.Run()
}

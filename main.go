package main

import (
	"github.com/gin-gonic/gin"
	"github.com/shardofarc/go-auth-jwt/controllers"
	"github.com/shardofarc/go-auth-jwt/initializers"
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
	r.GET("/generateTokens", controllers.GenerateTokens)

	r.Run()
}

package main

import (
	"fmt"
	"os"

	routers "github.com/sharvan/gojwt/routers"

	"github.com/gin-gonic/gin"
)

func main() {

	port := os.Getenv("PORT")
	if port == "" {
		port := "8000"
		fmt.Println("Lsting to Port :", port)
	}
	routes := gin.New()
	routes.Use(gin.Logger())

	routers.AuthRoutes(routes)
	routers.UserRoutes(routes)
	routes.Run(":" + port)
}

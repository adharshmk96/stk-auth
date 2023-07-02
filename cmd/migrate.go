package cmd

import (
	"fmt"

	migdbEntities "github.com/adharshmk96/migdb/pkg/entities"
	migdbService "github.com/adharshmk96/migdb/pkg/service"
	migdbFs "github.com/adharshmk96/migdb/pkg/storage/fs"
	migdbSqlite "github.com/adharshmk96/migdb/pkg/storage/sqlite"
	migdbUtils "github.com/adharshmk96/migdb/pkg/utils"
	"github.com/adharshmk96/stk-auth/pkg/infra"
	"github.com/adharshmk96/stk/pkg/db"
	"github.com/spf13/cobra"
)

const (
	MITRATION_FOLDER_PATH = "./migrations"
	DATABASE              = migdbEntities.DBsqlite3
)

var config = infra.GetConfig()

func executeUpMigration(numberOfMigrationsToApply int) {
	// TODO: add support for other databases

	conn := db.GetSqliteConnection(config.SQLITE_FILE_PATH)

	fsRepo := migdbFs.NewFileSystemRepo(MITRATION_FOLDER_PATH, DATABASE)
	dbRepo := migdbSqlite.NewSqliteRepo(conn)

	migrator, err := migdbService.NewDBMigratorService(dbRepo, fsRepo)
	if err != nil {
		fmt.Printf("Error initializing migrator: %v\n", err)
		return
	}

	fmt.Println("Running migration up on...")
	migrator.MigrateUp(numberOfMigrationsToApply)
	fmt.Println("Done.")
}

var migrateCmd = &cobra.Command{
	Use:   "migrate [number]",
	Short: "Perform the foward migration ( runs all files after the previously applied migrations )",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		numberOfMigrationsToApply := migdbUtils.GetNumberFromArgs(args, 0)

		executeUpMigration(numberOfMigrationsToApply)
	},
}

func init() {
	rootCmd.AddCommand(migrateCmd)
}
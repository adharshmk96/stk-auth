package cmd

import (
	"log"
	"path/filepath"
	"strconv"

	"github.com/adharshmk96/stk-auth/pkg/infra"
	"github.com/adharshmk96/stk/pkg/db"
	"github.com/adharshmk96/stk/pkg/migrator"
	"github.com/adharshmk96/stk/pkg/migrator/dbrepo"
	"github.com/adharshmk96/stk/pkg/migrator/fsrepo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var config = infra.GetConfig()

func getNumberFromArgs(args []string, defaultValue int) int {
	if len(args) == 0 {
		return defaultValue
	}
	num, err := strconv.Atoi(args[0])
	if err != nil {
		return defaultValue
	}
	return num
}

// migrateCmd represents the mkconfig command
var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Perform forward migration from the files in the migrations folder",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		rootDirectory := viper.GetString("migrator.workdir")
		dbChoice := viper.GetString("migrator.database")
		log.Println("selected database: ", dbChoice)

		dryRun := cmd.Flag("dry-run").Value.String() == "true"

		numToMigrate := getNumberFromArgs(args, 0)

		// Select based on the database
		dbType := migrator.SelectDatabase(dbChoice)

		extention := migrator.SelectExtention(dbType)
		subDirectory := migrator.SelectSubDirectory(dbType)
		fsRepo := fsrepo.NewFSRepo(filepath.Join(rootDirectory, subDirectory), extention)

		conn := db.GetSqliteConnection(config.SQLITE_FILE_PATH)
		dbRepo := dbrepo.NewSQLiteRepo(conn)

		log.Println("Applying migrations up...")

		config := &migrator.MigratorConfig{
			NumToMigrate: numToMigrate,
			DryRun:       dryRun,

			FSRepo: fsRepo,
			DBRepo: dbRepo,
		}

		_, err := migrator.MigrateUp(config)
		if err != nil {
			log.Fatal(err)
			return
		}

		log.Println("Migrated to database successfully.")

	},
}

func init() {
	migrateCmd.Flags().Bool("dry-run", false, "dry run, do not generate files")
	rootCmd.AddCommand(migrateCmd)
}

using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Vulpes.Plugins.Microsoft365Audit.Data;

#nullable disable

namespace Vulpes.Plugins.Microsoft365Audit.Data.Migrations
{
    [DbContext(typeof(AuditDbContext))]
    [Migration("20261112033000_BotTokenExpiry")]
    public class BotTokenExpiry : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "ExpiresAt",
                table: "BotTokens",
                type: "INTEGER",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(name: "ExpiresAt", table: "BotTokens");
        }
    }
}

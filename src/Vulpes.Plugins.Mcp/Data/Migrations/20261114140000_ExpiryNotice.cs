using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Vulpes.Plugins.Mcp.Data;

#nullable disable

namespace Vulpes.Plugins.Mcp.Data.Migrations;

[DbContext(typeof(McpDbContext))]
[Migration("20261114140000_ExpiryNotice")]
public class ExpiryNotice : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<long>(
            name: "ExpiryNoticeSentAt",
            table: "BotTokens",
            type: "INTEGER",
            nullable: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(name: "ExpiryNoticeSentAt", table: "BotTokens");
    }
}

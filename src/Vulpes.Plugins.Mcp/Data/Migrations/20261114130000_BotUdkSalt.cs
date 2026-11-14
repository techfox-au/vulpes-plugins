using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Vulpes.Plugins.Mcp.Data;

#nullable disable

namespace Vulpes.Plugins.Mcp.Data.Migrations;

[DbContext(typeof(McpDbContext))]
[Migration("20261114130000_BotUdkSalt")]
public class BotUdkSalt : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<byte[]>(
            name: "UserDataKeySalt",
            table: "BotTokens",
            type: "BLOB",
            nullable: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(name: "UserDataKeySalt", table: "BotTokens");
    }
}

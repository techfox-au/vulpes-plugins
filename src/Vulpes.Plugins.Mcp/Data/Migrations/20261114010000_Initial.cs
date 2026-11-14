using System;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Vulpes.Plugins.Mcp.Data;

#nullable disable

namespace Vulpes.Plugins.Mcp.Data.Migrations;

[DbContext(typeof(McpDbContext))]
[Migration("20261114010000_Initial")]
public class Initial : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "BotTokens",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "TEXT", nullable: false),
                Name = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                TokenHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                Prefix = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                CreatedAt = table.Column<long>(type: "INTEGER", nullable: false),
                ExpiresAt = table.Column<long>(type: "INTEGER", nullable: true),
                LastUsedAt = table.Column<long>(type: "INTEGER", nullable: true),
                RevokedAt = table.Column<long>(type: "INTEGER", nullable: true),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_BotTokens", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_BotTokens_TokenHash",
            table: "BotTokens",
            column: "TokenHash",
            unique: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "BotTokens");
    }
}

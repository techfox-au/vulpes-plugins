using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Vulpes.Plugins.Microsoft365Audit.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialAudit : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Tenants",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    DisplayName = table.Column<string>(type: "TEXT", maxLength: 120, nullable: false),
                    TenantId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ClientId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    CredentialType = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    ProtectedSecret = table.Column<string>(type: "TEXT", nullable: true),
                    ProtectedCertificate = table.Column<string>(type: "TEXT", nullable: true),
                    ProtectedCertificatePassword = table.Column<string>(type: "TEXT", nullable: true),
                    Cloud = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    LookbackDays = table.Column<int>(type: "INTEGER", nullable: false),
                    SettingsJson = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedAt = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedAt = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    LastTestAt = table.Column<long>(type: "INTEGER", nullable: true),
                    LastTestResultJson = table.Column<string>(type: "TEXT", nullable: true),
                    DiscoveredName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Tenants", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Checkpoints",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    Watermark = table.Column<long>(type: "INTEGER", nullable: true),
                    StateJson = table.Column<string>(type: "TEXT", nullable: true),
                    LastRunAt = table.Column<long>(type: "INTEGER", nullable: true),
                    LastSuccessAt = table.Column<long>(type: "INTEGER", nullable: true),
                    LastStatus = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    LastError = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    LastCount = table.Column<int>(type: "INTEGER", nullable: false),
                    TotalCount = table.Column<long>(type: "INTEGER", nullable: false),
                    NextRunAt = table.Column<long>(type: "INTEGER", nullable: true),
                    ConsecutiveFailures = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Checkpoints", x => new { x.TenantId, x.Source });
                    table.ForeignKey(
                        name: "FK_Checkpoints_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RunLog",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    StartedAt = table.Column<long>(type: "INTEGER", nullable: false),
                    FinishedAt = table.Column<long>(type: "INTEGER", nullable: true),
                    Status = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    Count = table.Column<int>(type: "INTEGER", nullable: false),
                    Duplicates = table.Column<int>(type: "INTEGER", nullable: false),
                    Failed = table.Column<int>(type: "INTEGER", nullable: false),
                    Alerts = table.Column<int>(type: "INTEGER", nullable: false),
                    Error = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RunLog", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RunLog_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_RunLog_StartedAt",
                table: "RunLog",
                column: "StartedAt");

            migrationBuilder.CreateIndex(
                name: "IX_RunLog_TenantId",
                table: "RunLog",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Tenants_TenantId",
                table: "Tenants",
                column: "TenantId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Checkpoints");

            migrationBuilder.DropTable(
                name: "RunLog");

            migrationBuilder.DropTable(
                name: "Tenants");
        }
    }
}

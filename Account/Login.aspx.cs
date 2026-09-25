using System;
using System.IO;
using System.Text;
using System.Web.UI;
using System.Xml;
using System.Security.Cryptography;
using CyberApp_FIA.Services;

namespace CyberApp_FIA.Account
{
    /// <summary>
    /// Login page code-behind.
    /// Authenticates a user against an XML store using PBKDF2 password verification,
    /// applies temporary login lockout after repeated failures, sets session variables,
    /// and redirects to a role-based landing page.
    /// </summary>
    public partial class Login : Page
    {
        // Protect read-modify-write operations on users.xml within this application process.
        private static readonly object UsersFileLock = new object();

        private const string GenericLoginError =
            "<span style='color:#c21d1d'>Invalid email or password.</span>";

        /// <summary>
        /// Physical path to the XML user store (~/App_Data/users.xml).
        /// </summary>
        private string XmlPath => Server.MapPath("~/App_Data/users.xml");

        protected void BtnLogin_Click(object sender, EventArgs e)
        {
            if (!Page.IsValid) return;

            if (!File.Exists(XmlPath))
            {
                // Do not disclose account information when the store is unavailable.
                FormMessage.Text = GenericLoginError;
                return;
            }

            var emailLower = (Email.Text ?? "").Trim().ToLowerInvariant();

            // Keep lookup, lockout check, verification, update, and save together.
            lock (UsersFileLock)
            {
                var doc = new XmlDocument();
                doc.Load(XmlPath);

                var userNode = doc.SelectSingleNode(
                    $"/users/user[translate(email,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='{emailLower}']");

                // Locked accounts receive the same response as all other failures.
                if (userNode != null &&
                    LoginRateLimiting.IsLockedOut(
                        (XmlElement)userNode,
                        DateTime.UtcNow))
                {
                    FormMessage.Text = GenericLoginError;
                    return;
                }

                if (userNode == null)
                {
                    LogUnknownEmailFailure(emailLower);
                    FormMessage.Text = GenericLoginError;
                    return;
                }

                var userElement = (XmlElement)userNode;
                var saltB64 = userElement["passwordSalt"]?.InnerText ?? "";
                var hashB64 = userElement["passwordHash"]?.InnerText ?? "";

                if (string.IsNullOrEmpty(saltB64) ||
                    string.IsNullOrEmpty(hashB64))
                {
                    // Do not reveal that the email belongs to an account.
                    FormMessage.Text = GenericLoginError;
                    return;
                }

                byte[] salt;
                byte[] storedHash;

                try
                {
                    salt = Convert.FromBase64String(saltB64);
                    storedHash = Convert.FromBase64String(hashB64);
                }
                catch
                {
                    // Do not reveal that the email belongs to an account.
                    FormMessage.Text = GenericLoginError;
                    return;
                }

                var enteredHash = HashPassword(Password.Text, salt);

                if (!SecureEquals(storedHash, enteredHash))
                {
                    LogExistingAccountFailure(userElement, emailLower);

                    LoginRateLimiting.RecordFailure(
                        doc,
                        userElement,
                        DateTime.UtcNow);

                    doc.Save(XmlPath);

                    FormMessage.Text = GenericLoginError;
                    return;
                }

                // A successful login clears consecutive failures and any lockout.
                LoginRateLimiting.RecordSuccess(doc, userElement);
                doc.Save(XmlPath);

                var id = userElement.GetAttribute("id");
                var role = userElement.GetAttribute("role");

                Session["UserId"] = id;
                Session["Role"] = role;
                Session["Email"] = emailLower;
                Session["University"] = userElement["university"]?.InnerText ?? "";

                LogSuccessfulLogin(role);
                RedirectByRole(role);
            }
        }

        private void LogUnknownEmailFailure(string emailLower)
        {
            try
            {
                var auditPath = Server.MapPath("~/App_Data/Audit_Log/UnvAdminAudit.xml");
                EnsureAuditFile(auditPath);

                var auditDoc = new XmlDocument();
                auditDoc.Load(auditPath);

                var entry = auditDoc.CreateElement("entry");
                entry.SetAttribute("id", "log-" + Guid.NewGuid().ToString("N"));
                entry.SetAttribute("university", "");
                entry.SetAttribute("role", "Unknown");
                entry.SetAttribute("type", "Sign In Failed (Unknown Email)");
                entry.SetAttribute("timestamp", DateTime.UtcNow.ToString("o"));
                entry.SetAttribute("email", emailLower);
                entry.SetAttribute("firstName", "");

                var details = auditDoc.CreateElement("details");
                details.InnerText = "Sign-in attempt with an email address that does not exist in users.xml.";
                entry.AppendChild(details);
                auditDoc.DocumentElement.AppendChild(entry);
                auditDoc.Save(auditPath);
            }
            catch
            {
                // Audit logging is best-effort.
            }
        }

        private void LogExistingAccountFailure(
            XmlElement userElement,
            string emailLower)
        {
            try
            {
                var auditPath = Server.MapPath("~/App_Data/Audit_Log/UnvAdminAudit.xml");
                EnsureAuditFile(auditPath);

                var auditDoc = new XmlDocument();
                auditDoc.Load(auditPath);

                var role = userElement.GetAttribute("role") ?? "";
                var entry = auditDoc.CreateElement("entry");
                entry.SetAttribute("id", "log-" + Guid.NewGuid().ToString("N"));
                entry.SetAttribute("university", userElement["university"]?.InnerText ?? "");
                entry.SetAttribute("role", string.IsNullOrWhiteSpace(role) ? "Unknown" : role);
                entry.SetAttribute("type", "Sign In Failed (Bad Password)");
                entry.SetAttribute("timestamp", DateTime.UtcNow.ToString("o"));
                entry.SetAttribute("email", emailLower);
                entry.SetAttribute("firstName", userElement["firstName"]?.InnerText ?? "");

                var details = auditDoc.CreateElement("details");
                details.InnerText = "Incorrect password entered for existing account during sign in.";
                entry.AppendChild(details);
                auditDoc.DocumentElement.AppendChild(entry);
                auditDoc.Save(auditPath);
            }
            catch
            {
                // Audit logging is best-effort.
            }
        }

        private void LogSuccessfulLogin(string role)
        {
            var normalizedRole = (role ?? string.Empty).Trim();

            if (!normalizedRole.Equals("Participant", StringComparison.OrdinalIgnoreCase) &&
                !normalizedRole.Equals("Helper", StringComparison.OrdinalIgnoreCase) &&
                !normalizedRole.Equals("UniversityAdmin", StringComparison.OrdinalIgnoreCase) &&
                !normalizedRole.Equals("SuperAdmin", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            try
            {
                UniversityAuditLogger.AppendForCurrentUser(
                    this,
                    "Sign In",
                    $"{normalizedRole} signed in.");
            }
            catch
            {
                // Audit logging is best-effort.
            }
        }

        private void RedirectByRole(string role)
        {
            switch ((role ?? "").Trim().ToLowerInvariant())
            {
                case "superadmin":
                    Response.Redirect("~/Account/SuperAdmin/SuperAdminHome.aspx");
                    break;
                case "universityadmin":
                    Response.Redirect("~/Account/UniversityAdmin/UniversityAdminHome.aspx");
                    break;
                case "helper":
                    Response.Redirect("~/Account/Helper/Home.aspx");
                    break;
                case "participant":
                default:
                    Response.Redirect("~/Account/Participant/SelectEvent.aspx");
                    break;
            }
        }

        private static void EnsureAuditFile(string auditPath)
        {
            var auditDir = Path.GetDirectoryName(auditPath);
            if (!string.IsNullOrEmpty(auditDir) && !Directory.Exists(auditDir))
            {
                Directory.CreateDirectory(auditDir);
            }

            if (!File.Exists(auditPath))
            {
                File.WriteAllText(
                    auditPath,
                    "<?xml version='1.0' encoding='utf-8'?><auditLog version='1'></auditLog>",
                    Encoding.UTF8);
            }
        }

        private static byte[] HashPassword(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000))
            {
                return pbkdf2.GetBytes(32);
            }
        }

        private static bool SecureEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;

            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}

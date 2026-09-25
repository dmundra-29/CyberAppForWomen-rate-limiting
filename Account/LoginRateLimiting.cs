using System;
using System.Globalization;
using System.Xml;

namespace CyberApp_FIA.Account
{
    /// <summary>
    /// Login lockout state stored on a user element in users.xml.
    /// </summary>
    internal static class LoginRateLimiting
    {
        // Test policy: five failures cause a temporary lockout.
        internal const int MaxFailedAttempts = 5;
        internal static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

        private const string FailedLoginCountElement = "failedLoginCount";
        private const string LockoutUntilElement = "lockoutUntilUtc";

        internal static bool IsLockedOut(XmlElement user, DateTime utcNow)
        {
            if (user == null) return false;

            var until = ReadUtc(user, LockoutUntilElement);
            if (!until.HasValue) return false;

            if (until.Value > utcNow)
            {
                return true;
            }

            // Expired locks are cleared on the next login attempt.
            ClearLockout(user);
            return false;
        }

        internal static void RecordFailure(
            XmlDocument document,
            XmlElement user,
            DateTime utcNow)
        {
            if (document == null) throw new ArgumentNullException("document");
            if (user == null) throw new ArgumentNullException("user");

            var count = ReadInt(user, FailedLoginCountElement) + 1;
            SetChildText(
                document,
                user,
                FailedLoginCountElement,
                count.ToString(CultureInfo.InvariantCulture));

            if (count >= MaxFailedAttempts)
            {
                var lockoutUntil = utcNow
                    .Add(LockoutDuration)
                    .ToString("o", CultureInfo.InvariantCulture);

                SetChildText(
                    document,
                    user,
                    LockoutUntilElement,
                    lockoutUntil);
            }
        }

        internal static void RecordSuccess(
            XmlDocument document,
            XmlElement user)
        {
            if (document == null) throw new ArgumentNullException("document");
            if (user == null) throw new ArgumentNullException("user");

            ClearLockout(document, user);
        }

        internal static void ClearLockout(XmlElement user)
        {
            if (user == null) return;

            var document = user.OwnerDocument;
            if (document != null)
            {
                ClearLockout(document, user);
            }
        }

        internal static void ClearLockout(
            XmlDocument document,
            XmlElement user)
        {
            if (document == null) throw new ArgumentNullException("document");
            if (user == null) throw new ArgumentNullException("user");

            SetChildText(document, user, FailedLoginCountElement, "0");
            SetChildText(document, user, LockoutUntilElement, "");
        }

        private static int ReadInt(XmlElement user, string childName)
        {
            int value;
            return int.TryParse(
                       user[childName]?.InnerText,
                       NumberStyles.Integer,
                       CultureInfo.InvariantCulture,
                       out value) && value >= 0
                ? value
                : 0;
        }

        private static DateTime? ReadUtc(XmlElement user, string childName)
        {
            DateTime value;

            if (!DateTime.TryParse(
                    user[childName]?.InnerText,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal |
                    DateTimeStyles.AdjustToUniversal,
                    out value))
            {
                return null;
            }

            return value;
        }

        private static void SetChildText(
            XmlDocument document,
            XmlElement parent,
            string childName,
            string value)
        {
            var child = parent[childName];

            if (child == null)
            {
                child = document.CreateElement(childName);
                parent.AppendChild(child);
            }

            child.InnerText = value ?? "";
        }
    }
}

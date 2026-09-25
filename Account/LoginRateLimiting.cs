using System;
using System.Globalization;
using System.Xml;

namespace CyberApp_FIA.Account
{
    /// <summary>
    /// Login lockout state stored on a user element in users.xml.
    ///
    /// RATE LIMITING CHANGE: This helper is deliberately independent of the login page so
    /// the same lockout-reset operation can be used by owner and administrator reset flows.
    /// </summary>
    internal static class LoginRateLimiting
    {
        // RATE LIMITING CHANGE: Keep policy values centralized for review and future tuning.
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

            // RATE LIMITING CHANGE: Expired locks are cleared lazily on the next login.
            ClearLockout(user);
            return false;
        }

        internal static void RecordFailure(XmlDocument document, XmlElement user, DateTime utcNow)
        {
            if (document == null) throw new ArgumentNullException("document");
            if (user == null) throw new ArgumentNullException("user");

            var count = ReadInt(user, FailedLoginCountElement) + 1;
            SetChildText(document, user, FailedLoginCountElement, count.ToString(CultureInfo.InvariantCulture));

            // RATE LIMITING CHANGE: Lock only after the configured number of failures.
            if (count >= MaxFailedAttempts)
            {
                var lockoutUntil = utcNow.Add(LockoutDuration).ToString("o", CultureInfo.InvariantCulture);
                SetChildText(document, user, LockoutUntilElement, lockoutUntil);
            }
        }

        internal static void RecordSuccess(XmlDocument document, XmlElement user)
        {
            if (document == null) throw new ArgumentNullException("document");
            if (user == null) throw new ArgumentNullException("user");

            // RATE LIMITING CHANGE: A successful login resets the consecutive-failure count.
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

        internal static void ClearLockout(XmlDocument document, XmlElement user)
        {
            if (document == null) throw new ArgumentNullException("document");
            if (user == null) throw new ArgumentNullException("user");

            // PASSWORD RESET CHANGE: A valid password reset is an explicit recovery path
            // and must work even while the account is locked.
            SetChildText(document, user, FailedLoginCountElement, "0");
            SetChildText(document, user, LockoutUntilElement, "");
        }

        private static int ReadInt(XmlElement user, string childName)
        {
            int value;
            return int.TryParse(user[childName]?.InnerText, NumberStyles.Integer,
                CultureInfo.InvariantCulture, out value) && value >= 0 ? value : 0;
        }

        private static DateTime? ReadUtc(XmlElement user, string childName)
        {
            DateTime value;
            if (!DateTime.TryParse(user[childName]?.InnerText, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out value))
            {
                return null;
            }

            return value;
        }

        private static void SetChildText(XmlDocument document, XmlElement parent, string childName, string value)
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

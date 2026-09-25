# CyberAppForWomen rate-limiting changes

This repository contains the rate-limiting support files prepared for later copying into `feminineintelligenceagency/CyberAppForWomen`.

The source repository was not modified. All new security-related code is marked with comments beginning with `RATE LIMITING CHANGE` or `PASSWORD RESET CHANGE`.

## Integration points

1. In `Account/Login.aspx.cs`, after `userNode` is located and before reading/verifying the password, call `LoginRateLimiting.IsLockedOut(userNode, DateTime.UtcNow)`.
2. In the bad-password branch, call `LoginRateLimiting.RecordFailure(...)` and save `users.xml` while holding the same application-wide file lock.
3. After successful authentication, call `LoginRateLimiting.RecordSuccess(...)` and save `users.xml`.
4. Use the same generic `Invalid email or password.` response for unknown emails, wrong passwords, and locked accounts.
5. In every password-reset handler, call `LoginRateLimiting.ClearLockout(user)` before saving the updated password hash and salt.

The helper stores `failedLoginCount` and `lockoutUntilUtc` as children of each `<user>` element in `users.xml`.

# Password reset integration

Add the following call to every password reset handler immediately after the new password hash and salt are written, before `doc.Save(...)`.

```csharp
// PASSWORD RESET CHANGE: Password recovery remains available during login lockout.
// A successful reset clears the failed-login counter and lockout timestamp.
LoginRateLimiting.ClearLockout(doc, user);
```

For the existing administrative reset handler, the relevant section in `Account/SuperAdmin/PasswordReset.aspx.cs` becomes:

```csharp
SetOrCreateChildText(doc, user, "passwordHash", passwordHash);
SetOrCreateChildText(doc, user, "passwordSalt", passwordSalt);

// PASSWORD RESET CHANGE: Admin and owner recovery paths clear lockout state.
LoginRateLimiting.ClearLockout(doc, user);

doc.Save(UsersXmlPath);
```

The repository currently contains an administrative reset page, but an owner-facing reset flow still needs an expiring, single-use token mechanism. The owner-facing flow must not require a successful login and should call the same `ClearLockout` method after validating the token and new password.

Do not expose whether an email exists when requesting a reset. Return one generic message such as:

```text
If an account matches that email, reset instructions will be sent.
```

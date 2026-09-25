# Login.aspx.cs integration snippets

These snippets are intended for `Account/Login.aspx.cs`. They are separated from the original file so the changes can be reviewed and copied into the source repository without overwriting unrelated work.

## Add imports and a shared write lock

```csharp
// RATE LIMITING CHANGE: Protect read-modify-write operations on users.xml.
private static readonly object UsersFileLock = new object();
```

## Add after user lookup and before password verification

```csharp
// RATE LIMITING CHANGE: Locked accounts use the same response as every other
// authentication failure so the login endpoint does not reveal account state.
if (userNode != null && LoginRateLimiting.IsLockedOut((XmlElement)userNode, DateTime.UtcNow))
{
    FormMessage.Text = "<span style='color:#c21d1d'>Invalid email or password.</span>";
    return;
}
```

The lock check should be performed while holding `UsersFileLock` if the surrounding implementation is changed to keep the XML document open during the whole authentication operation.

## Replace the bad-password state update

Inside the existing `if (!SecureEquals(storedHash, enteredHash))` branch, after the audit entry and before returning:

```csharp
// RATE LIMITING CHANGE: Count only failed attempts for a known account.
lock (UsersFileLock)
{
    var latestDoc = new XmlDocument();
    latestDoc.Load(XmlPath);
    var latestUser = latestDoc.SelectSingleNode(
        $"/users/user[translate(email,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='{emailLower}']") as XmlElement;

    if (latestUser != null)
    {
        LoginRateLimiting.RecordFailure(latestDoc, latestUser, DateTime.UtcNow);
        latestDoc.Save(XmlPath);
    }
}
```

Use the generic existing response:

```csharp
FormMessage.Text = "<span style='color:#c21d1d'>Invalid email or password.</span>";
return;
```

## Reset state after successful authentication

Before session initialization or immediately after it:

```csharp
// RATE LIMITING CHANGE: Successful authentication clears consecutive failures.
lock (UsersFileLock)
{
    var latestDoc = new XmlDocument();
    latestDoc.Load(XmlPath);
    var latestUser = latestDoc.SelectSingleNode(
        $"/users/user[translate(email,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='{emailLower}']") as XmlElement;

    if (latestUser != null)
    {
        LoginRateLimiting.RecordSuccess(latestDoc, latestUser);
        latestDoc.Save(XmlPath);
    }
}
```

For stronger concurrency behavior, refactor the existing login handler so lookup, lock check, password verification, counter update, and save all happen under one lock rather than loading `users.xml` more than once.

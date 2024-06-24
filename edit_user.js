<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit User</title>
    <link rel="stylesheet" href="/styles.css">
</head>
<body>
    <header>
        <div class="navbar">
            <div class="logo">CauseConnect</div>
            <ul class="nav-links">
                <li><a href="/">Home</a></li>
                <li><a href="/about">About</a></li>
                <li><a href="/events">Events</a></li>
                <li><a href="/faqs">FAQs</a></li>
                <% if (user) { %>
                    <li><a href="/profile">Profile</a></li>
                    <li><a href="/logout">Logout</a></li>
                <% } else { %>
                    <li><a href="/login">Login</a></li>
                    <li><a href="/signup" class="sign-up">Sign Up</a></li>
                <% } %>
            </ul>
        </div>
    </header>
    <main>
        <h1>Edit User</h1>
        <form action="/admin/edit/<%= user.id %>" method="POST">
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" value="<%= user.email %>" required>
            <label for="role">Role:</label>
            <select id="role" name="role" required>
                <option value="user" <%= user.role === 'user' ? 'selected' : '' %>>User</option>
                <option value="manager" <%= user.role === 'manager' ? 'selected' : '' %>>Manager</option>
                <option value="admin" <%= user.role === 'admin' ? 'selected' : '' %>>Admin</option>
            </select>
            <button type="submit">Update User</button>
        </form>
        <form action="/admin/delete/<%= user.id %>" method="POST">
            <button type="submit" class="delete-button">Delete User</button>
        </form>
    </main>
</body>
</html>

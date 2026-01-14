<?php
declare(strict_types=1);

require_once __DIR__ . '/functions/security.php';

start_secure_session();
set_security_headers();

$errors = [];
$success = isset($_GET['success']) && $_GET['success'] === '1';
$username = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $success = false;
    $username = trim((string) ($_POST['username'] ?? ''));
    $email = trim((string) ($_POST['email'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $passwordConfirm = (string) ($_POST['password_confirm'] ?? '');

    if ($username == '') {
        $errors[] = 'Username is required.';
    }

    if ($email == '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'A valid email is required.';
    }

    if ($password == '') {
        $errors[] = 'Password is required.';
    } elseif (strlen($password) < 8) {
        $errors[] = 'Password must be at least 8 characters.';
    }

    if ($passwordConfirm == '') {
        $errors[] = 'Please confirm your password.';
    } elseif ($password !== $passwordConfirm) {
        $errors[] = 'Passwords do not match.';
    }

    if (!$errors) {
        $pdo = require __DIR__ . '/connection/dbconn.php';
        require_once __DIR__ . '/functions/queries.php';

        if (find_user_by_username($pdo, $username)) {
            $errors[] = 'Username is already in use.';
        }

        if (find_user_by_email($pdo, $email)) {
            $errors[] = 'Email is already in use.';
        }

        if (!$errors) {
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            create_user($pdo, $username, $email, $passwordHash);
            header('Location: register.php?success=1');
            exit;
        }
    }
}

?>
<!DOCTYPE html>
<html class="dark" lang="en">

<head>
    <meta charset="utf-8" />
    <meta content="width=device-width, initial-scale=1.0" name="viewport" />
    <title>Secure Vault Registration</title>
    <script>
        (function() {
            const stored = localStorage.getItem('theme');
            if (stored === 'light') {
                document.documentElement.classList.remove('dark');
            } else {
                document.documentElement.classList.add('dark');
            }
        })();
    </script>
    <link rel="stylesheet" href="assets/tailwind.css" />
    <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&amp;display=swap" rel="stylesheet" />
    <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@200;400;500;600;700;800&amp;display=swap" rel="stylesheet" />
    <style>
        .material-symbols-outlined {
            font-variation-settings: 'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24;
        }
        body {
            background-image: radial-gradient(circle at 50% 50%, rgba(19, 70, 88, 0.05) 0%, transparent 100%);
        }
        .dark body {
            background-image: radial-gradient(circle at 50% 50%, rgba(19, 70, 88, 0.15) 0%, transparent 100%);
        }
    </style>
</head>

<body class="bg-background-light dark:bg-background-dark font-display min-h-screen flex flex-col items-center justify-center p-4">
    <div class="mb-10 text-center flex flex-col items-center">
        <div class="mb-4 bg-primary/10 dark:bg-primary/20 p-4 rounded-full">
            <span class="material-symbols-outlined text-4xl text-primary dark:text-sky-400">shield_lock</span>
        </div>
        <h2 class="text-xl font-bold text-slate-900 dark:text-white tracking-tight">Personal Vault</h2>
    </div>
    <main class="w-full max-w-[440px] z-10">
        <div class="relative bg-white dark:bg-vault-dark border border-slate-200 dark:border-vault-border rounded-2xl shadow-xl p-8 md:p-10">
            <button class="absolute right-4 top-4 p-2 rounded-lg border border-slate-200 dark:border-vault-border text-slate-500 hover:text-primary hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors" type="button" id="theme-toggle" aria-label="Toggle theme">
                <span class="material-symbols-outlined text-[20px]" data-theme-icon>dark_mode</span>
            </button>
            <div class="text-center mb-8">
                <h1 class="text-slate-900 dark:text-white text-2xl font-bold mb-2">Create Your Vault Account</h1>
                <p class="text-slate-500 dark:text-slate-400 text-sm">Set up a secure profile to store and protect your credentials.</p>
            </div>
            <?php if ($success): ?>
                <div class="mb-6 rounded-xl border border-emerald-200 bg-emerald-50 text-emerald-700 text-sm px-4 py-3">
                    Account created. <a class="font-bold hover:text-emerald-800" href="index.php">Sign in</a>
                </div>
            <?php endif; ?>
            <?php if ($errors): ?>
                <div class="mb-6 rounded-xl border border-rose-200 bg-rose-50 text-rose-700 text-sm px-4 py-3">
                    <p class="font-bold">We could not create your account.</p>
                    <ul class="mt-2 list-disc pl-5 space-y-1">
                        <?php foreach ($errors as $error): ?>
                            <li><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>
            <form class="space-y-6" method="post" action="">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') ?>" />
                <div class="flex flex-col gap-2">
                    <div class="flex justify-between items-center mb-1">
                        <label class="text-slate-700 dark:text-slate-300 text-xs font-bold uppercase tracking-wider">Username</label>
                    </div>
                    <div class="relative group">
                        <input autofocus="" class="form-input w-full rounded-xl border border-slate-200 dark:border-vault-border bg-slate-50 dark:bg-slate-900/50 focus:border-primary focus:ring-4 focus:ring-primary/10 h-14 px-5 text-lg font-medium outline-none transition-all dark:text-white placeholder:text-slate-300 dark:placeholder:text-slate-600" name="username" placeholder="vault_user" required="" type="text" autocomplete="username" value="<?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>" />
                    </div>
                </div>
                <div class="flex flex-col gap-2">
                    <div class="flex justify-between items-center mb-1">
                        <label class="text-slate-700 dark:text-slate-300 text-xs font-bold uppercase tracking-wider">Email</label>
                    </div>
                    <div class="relative group">
                        <input class="form-input w-full rounded-xl border border-slate-200 dark:border-vault-border bg-slate-50 dark:bg-slate-900/50 focus:border-primary focus:ring-4 focus:ring-primary/10 h-14 px-5 text-lg font-medium outline-none transition-all dark:text-white placeholder:text-slate-300 dark:placeholder:text-slate-600" name="email" placeholder="you@example.com" required="" type="email" autocomplete="email" value="<?= htmlspecialchars($email, ENT_QUOTES, 'UTF-8') ?>" />
                    </div>
                </div>
                <div class="flex flex-col gap-2">
                    <div class="flex justify-between items-center mb-1">
                        <label class="text-slate-700 dark:text-slate-300 text-xs font-bold uppercase tracking-wider">Master Password</label>
                    </div>
                    <div class="relative group">
                        <input class="form-input w-full rounded-xl border border-slate-200 dark:border-vault-border bg-slate-50 dark:bg-slate-900/50 focus:border-primary focus:ring-4 focus:ring-primary/10 h-14 px-5 pr-12 text-lg font-medium outline-none transition-all dark:text-white placeholder:text-slate-300 dark:placeholder:text-slate-600" id="register-password" name="password" placeholder="At least 8 characters" required="" type="password" autocomplete="new-password" />
                        <button class="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-primary dark:hover:text-sky-400 transition-colors toggle-input-password" type="button" data-target="register-password" aria-label="Show password">
                            <span class="material-symbols-outlined">visibility</span>
                        </button>
                    </div>
                </div>
                <div class="flex flex-col gap-2">
                    <div class="flex justify-between items-center mb-1">
                        <label class="text-slate-700 dark:text-slate-300 text-xs font-bold uppercase tracking-wider">Confirm Password</label>
                    </div>
                    <div class="relative group">
                        <input class="form-input w-full rounded-xl border border-slate-200 dark:border-vault-border bg-slate-50 dark:bg-slate-900/50 focus:border-primary focus:ring-4 focus:ring-primary/10 h-14 px-5 pr-12 text-lg font-medium outline-none transition-all dark:text-white placeholder:text-slate-300 dark:placeholder:text-slate-600" id="register-password-confirm" name="password_confirm" placeholder="Re-enter password" required="" type="password" autocomplete="new-password" />
                        <button class="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-primary dark:hover:text-sky-400 transition-colors toggle-input-password" type="button" data-target="register-password-confirm" aria-label="Show password">
                            <span class="material-symbols-outlined">visibility</span>
                        </button>
                    </div>
                </div>
                <button class="w-full h-14 bg-primary hover:bg-slate-800 dark:bg-sky-600 dark:hover:bg-sky-500 text-white rounded-xl font-bold text-base transition-all shadow-lg shadow-primary/10 flex items-center justify-center gap-2 group" type="submit">
                    <span>Create Account</span>
                    <span class="material-symbols-outlined text-xl group-hover:translate-x-1 transition-transform">arrow_forward</span>
                </button>
                <div class="text-center">
                    <a class="text-slate-400 dark:text-slate-500 text-xs font-medium hover:text-primary dark:hover:text-sky-400 transition-colors" href="index.php">Already have an account? Sign in</a>
                </div>
            </form>

        </div>
        <div class="mt-8 flex flex-col items-center gap-6">
            <div class="flex items-center gap-6 text-[10px] text-slate-400 dark:text-slate-500 font-bold uppercase tracking-widest">
                <a class="hover:text-primary dark:hover:text-sky-400 transition-colors" href="#">Privacy Policy</a>
                <span class="w-1 h-1 bg-slate-300 dark:bg-slate-700 rounded-full"></span>
                <a class="hover:text-primary dark:hover:text-sky-400 transition-colors" href="#">Security Audit</a>
                <span class="w-1 h-1 bg-slate-300 dark:bg-slate-700 rounded-full"></span>
                <a class="hover:text-primary dark:hover:text-sky-400 transition-colors" href="#">Help</a>
            </div>
        </div>
    </main>
    <footer class="mt-auto py-8 text-slate-400 dark:text-slate-600 text-[10px] tracking-widest uppercase">
        2024 Secure Vault - End-to-End Encrypted Access
    </footer>

    <script>
        (function () {
            const themeToggle = document.getElementById('theme-toggle');
            const themeIcon = themeToggle ? themeToggle.querySelector('[data-theme-icon]') : null;

            function applyTheme(theme) {
                const isDark = theme === 'dark';
                document.documentElement.classList.toggle('dark', isDark);
                if (themeIcon) {
                    themeIcon.textContent = isDark ? 'light_mode' : 'dark_mode';
                }
                if (themeToggle) {
                    themeToggle.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
                }
            }

            const stored = localStorage.getItem('theme');
            applyTheme(stored === 'light' ? 'light' : 'dark');

            if (themeToggle) {
                themeToggle.addEventListener('click', function () {
                    const nextTheme = document.documentElement.classList.contains('dark') ? 'light' : 'dark';
                    localStorage.setItem('theme', nextTheme);
                    applyTheme(nextTheme);
                });
            }

            document.querySelectorAll('.toggle-input-password').forEach(function (button) {
                const targetId = button.getAttribute('data-target');
                if (!targetId) {
                    return;
                }

                const input = document.getElementById(targetId);
                if (!input) {
                    return;
                }

                button.addEventListener('click', function () {
                    const isPassword = input.getAttribute('type') === 'password';
                    input.setAttribute('type', isPassword ? 'text' : 'password');
                    const icon = button.querySelector('.material-symbols-outlined');
                    if (icon) {
                        icon.textContent = isPassword ? 'visibility_off' : 'visibility';
                    }
                    button.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
                });
            });
        })();
    </script>
</body>

</html>

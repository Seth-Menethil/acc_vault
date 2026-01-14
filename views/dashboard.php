<?php

declare(strict_types=1);



require_once __DIR__ . '/../functions/security.php';

start_secure_session();
set_security_headers();



if (!isset($_SESSION['user_id'])) {

    header('Location: ../index.php');

    exit;
}



$pdo = require __DIR__ . '/../connection/dbconn.php';

require_once __DIR__ . '/../functions/queries.php';
require_once __DIR__ . '/../functions/crypto.php';

$userId = (int) $_SESSION['user_id'];


$addErrors = [];

$addSuccess = isset($_GET['added']) && $_GET['added'] === '1';

$addModalOpen = false;

$editErrors = [];

$editSuccess = isset($_GET['updated']) && $_GET['updated'] === '1';

$editModalOpen = false;

$deleteError = "";

$deleteSuccess = isset($_GET['deleted']) && $_GET['deleted'] === '1';

$formData = [

    'site_name' => '',

    'login_username' => '',

    'login_password' => '',

];

$editFormData = [

    'entry_id' => '',

    'site_name' => '',

    'login_username' => '',

    'login_password' => '',

];



if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $action = (string) ($_POST['action'] ?? '');

    $addSuccess = false;
    $editSuccess = false;
    $deleteSuccess = false;

    verify_csrf();



    if ($action === 'add_account') {

        $formData = [

            'site_name' => trim((string) ($_POST['site_name'] ?? '')),

            'login_username' => trim((string) ($_POST['login_username'] ?? '')),

            'login_password' => (string) ($_POST['login_password'] ?? ''),

        ];



        if ($formData['site_name'] == '') {

            $addErrors[] = 'Website name is required.';
        }



        if ($formData['login_username'] == '') {

            $addErrors[] = 'Username is required.';
        }



        if ($formData['login_password'] == '') {

            $addErrors[] = 'Password is required.';
        }



        if (!$addErrors) {
            try {
                $ciphertext = encrypt_secret($formData['login_password']);
            } catch (RuntimeException $e) {
                $addErrors[] = 'Unable to encrypt the password.';
            }
        }

        if (!$addErrors) {

            create_vault_entry(

                $pdo,

                $userId,

                $formData['site_name'],

                $formData['login_username'],

                $ciphertext,

                null,

                null,

                false

            );



            header('Location: dashboard.php?added=1');
            exit;
        }
    } elseif ($action === 'update_account') {

        $entryId = (int) ($_POST['entry_id'] ?? 0);

        $editFormData = [

            'entry_id' => (string) $entryId,

            'site_name' => trim((string) ($_POST['site_name'] ?? '')),

            'login_username' => trim((string) ($_POST['login_username'] ?? '')),

            'login_password' => (string) ($_POST['login_password'] ?? ''),

        ];



        if ($entryId <= 0) {

            $editErrors[] = 'Invalid account selected.';
        }



        if ($editFormData['site_name'] == '') {

            $editErrors[] = 'Website name is required.';
        }



        if ($editFormData['login_username'] == '') {

            $editErrors[] = 'Username is required.';
        }

        $passwordCiphertext = null;
        if (!$editErrors && $editFormData['login_password'] !== '') {
            try {
                $passwordCiphertext = encrypt_secret($editFormData['login_password']);
            } catch (RuntimeException $e) {
                $editErrors[] = 'Unable to encrypt the password.';
            }
        }

        if (!$editErrors) {

            $updated = update_vault_entry(

                $pdo,

                $userId,

                $entryId,

                $editFormData['site_name'],

                $editFormData['login_username'],

                $passwordCiphertext

            );



            if ($updated) {

                header('Location: dashboard.php?updated=1');
                exit;
            } else {

                $editErrors[] = 'Unable to update the account.';
            }
        }
    } elseif ($action === 'delete_account') {

        $entryId = (int) ($_POST['entry_id'] ?? 0);



        if ($entryId <= 0) {

            $deleteError = 'Invalid account selected.';
        } else {

            $deleted = delete_vault_entry($pdo, $userId, $entryId);

            if ($deleted) {

                header('Location: dashboard.php?deleted=1');
                exit;
            } else {

                $deleteError = 'Unable to delete the account.';
            }
        }
    }
}



$addModalOpen = (bool) $addErrors;

$editModalOpen = (bool) $editErrors;

$limit = 25;
$page = max(1, (int) ($_GET['page'] ?? 1));
$totalEntries = count_vault_entries($pdo, $userId);
$totalPages = max(1, (int) ceil($totalEntries / $limit));
$page = min($page, $totalPages);
$offset = ($page - 1) * $limit;
$entries = list_vault_entries($pdo, $userId, $limit, $offset);
$userLabel = $_SESSION['user_label'] ?? 'Vault User';
?>
<!DOCTYPE html>

<html class="dark" lang="en">



<head>

    <meta charset="utf-8" />

    <meta content="width=device-width, initial-scale=1.0" name="viewport" />

    <title>Vault - Simplified Password Dashboard</title>
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

    <link rel="stylesheet" href="../assets/tailwind.css" />

    <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&amp;display=swap" rel="stylesheet" />

    <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&amp;display=swap" rel="stylesheet" />

    <style>
        .material-symbols-outlined {

            font-variation-settings: 'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24;

        }



        .password-dots {

            letter-spacing: 0.25em;

        }



        .custom-scrollbar::-webkit-scrollbar {

            width: 4px;

        }



        .custom-scrollbar::-webkit-scrollbar-track {

            background: transparent;

        }



        .custom-scrollbar::-webkit-scrollbar-thumb {

            background: #2a3337;

            border-radius: 10px;

        }
    </style>

</head>



<body class="bg-background-light dark:bg-background-dark font-display text-slate-900 dark:text-slate-100 antialiased min-h-screen lg:h-screen overflow-y-auto lg:overflow-hidden">

    <div class="flex flex-col lg:flex-row min-h-screen lg:h-full w-full">

        <aside class="w-full lg:w-64 flex flex-col border-b lg:border-b-0 lg:border-r border-border-dark bg-background-light dark:bg-background-dark shrink-0">

            <div class="p-6">

                <div class="flex items-center gap-3 mb-6">

                    <div class="size-8 bg-primary rounded-lg flex items-center justify-center text-white">

                        <span class="material-symbols-outlined">shield_lock</span>

                    </div>

                    <div>

                        <h1 class="text-lg font-extrabold leading-none">Vault</h1>

                        <p class="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Secure Manager</p>

                    </div>

                </div>

                <nav class="flex flex-wrap lg:flex-col gap-2">

                    <div class="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-primary/10 text-primary dark:text-slate-100 font-semibold">

                        <span class="material-symbols-outlined text-[20px]">database</span>

                        <span class="text-sm">All Accounts</span>

                    </div>

                    <button class="w-full bg-primary text-white px-3 py-2.5 rounded-lg text-sm font-bold flex items-center justify-center gap-2 hover:brightness-110 active:scale-95 transition-all shadow-lg shadow-primary/20" type="button" id="open-add-account-modal">
                        <span class="material-symbols-outlined text-[18px]">add_circle</span>
                        Add Account
                    </button>

                    <button class="md:hidden w-full border border-border-dark text-slate-500 px-3 py-2.5 rounded-lg text-sm font-bold flex items-center justify-center gap-2 hover:bg-slate-100 dark:hover:bg-border-dark transition-all" type="button" data-theme-toggle aria-label="Toggle theme">
                        <span class="material-symbols-outlined text-[18px]" data-theme-icon>dark_mode</span>
                        Toggle Theme
                    </button>
                    
                </nav>

            </div>

            <div class="mt-auto p-6">
                <form method="post" action="../logout.php">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') ?>" />
                    <button class="w-full flex items-center justify-center gap-2 border border-border-dark text-slate-500 py-2.5 rounded-lg font-bold text-sm hover:bg-slate-100 dark:hover:bg-border-dark transition-all" type="submit">
                        <span class="material-symbols-outlined text-[18px]">logout</span>
                        Logout
                    </button>
                </form>
            </div>

        </aside>

        <main class="flex-1 flex flex-col bg-background-light dark:bg-background-dark min-w-0">

            <header class="border-b border-border-dark flex flex-col lg:flex-row lg:items-center lg:justify-between px-4 sm:px-8 py-4 gap-4 bg-background-light dark:bg-background-dark/50 backdrop-blur-md sticky top-0 z-10">

                <div class="flex items-center flex-1 w-full max-w-2xl">

                    <div class="relative w-full group">

                        <span class="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-[20px] transition-colors group-focus-within:text-primary">search</span>

                        <input class="w-full bg-slate-100 dark:bg-surface-dark border-none rounded-lg pl-10 pr-4 py-2 text-sm placeholder:text-slate-500 focus:ring-2 focus:ring-primary/20 transition-all" placeholder="Search accounts..." type="text" />

                    </div>

                </div>

                <div class="flex flex-wrap items-center gap-3 lg:ml-6">
                    <button class="hidden md:block p-2 rounded-lg border border-border-dark text-slate-500 hover:text-primary hover:bg-slate-100 dark:hover:bg-border-dark transition-colors" type="button" data-theme-toggle aria-label="Toggle theme">
                        <span class="material-symbols-outlined text-[22px]" data-theme-icon>dark_mode</span>
                    </button>
                    <div class="hidden sm:flex items-center border-l border-border-dark pl-4 gap-2">
                        <div class="flex flex-col items-end">
                            <span class="text-xs text-slate-500">Signed in as</span>
                            <span class="text-sm font-bold text-slate-700 dark:text-slate-200"><?= htmlspecialchars((string) $userLabel, ENT_QUOTES, 'UTF-8') ?></span>
                        </div>
                        <div class="size-8 rounded-full bg-cover bg-center border-2 border-primary/20 ml-2" style="background-image: url('https://lh3.googleusercontent.com/aida-public/AB6AXuBguSk_6sGJBm_EqJr1KYybmk-4JYeMdkE09Dw6nttAzZXaayRthqhGlUZMpZHvtu4Kd52v1p2DQCW7n244fo5ubO2r0a8wdC5BTSEd86kkUTMj2hZIrNxQcv3A-rIAHet87Ctqs2Ns8DPmhRpcZnPzW3k4pSnwa1ZGzx25JkQiHuy_ooorcaVWTkuRLjRSWw5Fcx0VD5Uqg728AIsYHPL2VAO4wpajgDlaao7FGW3y2TdLMojVNRLbKVAeAOJVyRuD2ZGIZHr9_4M')"></div>
                    </div>

                </div>

            </header>

            <div class="px-4 sm:px-8 pt-6">

                <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-6">

                    <div>

                        <h2 class="text-2xl font-extrabold">Online Accounts</h2>

                        <p class="text-sm text-slate-500 mt-1">Manage your secure website credentials</p>

                    </div>

                    <div class="flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-slate-400">

                        <span><?= htmlspecialchars((string) $totalEntries, ENT_QUOTES, 'UTF-8') ?> Total Items</span>

                    </div>

                </div>

            </div>

            <div class="flex-1 overflow-y-auto custom-scrollbar px-4 sm:px-8 pb-8">
                <div class="bg-white dark:bg-surface-dark rounded-xl border border-border-dark shadow-sm overflow-hidden">
                    <?php if ($addSuccess): ?>
                        <div class="px-6 py-3 border-b border-border-dark bg-emerald-50 text-emerald-700 text-xs font-semibold">Account added.</div>
                    <?php endif; ?>
                    <?php if ($editSuccess): ?>
                        <div class="px-6 py-3 border-b border-border-dark bg-emerald-50 text-emerald-700 text-xs font-semibold">Account updated.</div>
                    <?php endif; ?>
                    <?php if ($deleteSuccess): ?>
                        <div class="px-6 py-3 border-b border-border-dark bg-emerald-50 text-emerald-700 text-xs font-semibold">Account deleted.</div>
                    <?php endif; ?>
                    <?php if ($deleteError): ?>
                        <div class="px-6 py-3 border-b border-border-dark bg-rose-50 text-rose-700 text-xs font-semibold"><?= htmlspecialchars($deleteError, ENT_QUOTES, 'UTF-8') ?></div>
                    <?php endif; ?>

                    <div class="hidden md:block">

                        <table class="w-full text-left border-collapse">

                            <thead>

                                <tr class="bg-slate-50 dark:bg-background-dark/30 text-[11px] font-bold uppercase tracking-widest text-slate-500 border-b border-border-dark">

                                    <th class="px-6 py-4">Website</th>

                                    <th class="px-6 py-4">Username</th>

                                    <th class="px-6 py-4">Password</th>

                                    <th class="px-6 py-4 text-right">Actions</th>

                                </tr>

                            </thead>

                            <tbody class="divide-y divide-border-dark">

                                <?php if ($entries): ?>

                                    <?php foreach ($entries as $entry): ?>

                                        <?php $maskedPassword = str_repeat('*', 10); ?>

                                        <tr class="group hover:bg-slate-50 dark:hover:bg-primary/5 transition-colors">

                                            <td class="px-6 py-4">

                                                <div class="flex items-center gap-3">

                                                    <div class="text-sm font-bold"><?= htmlspecialchars((string) $entry['site_name'], ENT_QUOTES, 'UTF-8') ?></div>

                                                </div>

                                            </td>

                                            <td class="px-6 py-4">

                                                <div class="flex items-center gap-2">

                                                    <span class="text-sm text-slate-600 dark:text-slate-300"><?= htmlspecialchars((string) $entry['login_username'], ENT_QUOTES, 'UTF-8') ?></span>

                                                </div>

                                            </td>

                                            <td class="px-6 py-4">
                                                <div class="flex items-center gap-2" data-password-container data-entry-id="<?= (int) $entry['id'] ?>">
                                                    <span class="text-xs password-dots text-slate-400 font-mono" data-password-value data-password-mask="<?= htmlspecialchars($maskedPassword, ENT_QUOTES, 'UTF-8') ?>" data-visible="false"><?= htmlspecialchars($maskedPassword, ENT_QUOTES, 'UTF-8') ?></span>
                                                    <button class="material-symbols-outlined text-[16px] text-slate-300 hover:text-primary transition-all password-toggle" type="button" data-entry-id="<?= (int) $entry['id'] ?>" aria-label="Show password">visibility</button>
                                                </div>
                                            </td>

                                            <td class="px-6 py-4 text-right">

                                                <button class="p-2 rounded-lg text-slate-400 hover:text-primary hover:bg-primary/10 transition-all open-edit-account-modal" type="button" data-edit-account="true" data-entry-id="<?= (int) $entry['id'] ?>" data-site-name="<?= htmlspecialchars((string) $entry['site_name'], ENT_QUOTES, 'UTF-8') ?>" data-login-username="<?= htmlspecialchars((string) $entry['login_username'], ENT_QUOTES, 'UTF-8') ?>">
                                                    <span class="material-symbols-outlined text-[20px]">edit</span>
                                                </button>

                                            </td>

                                        </tr>

                                    <?php endforeach; ?>

                                <?php else: ?>

                                    <tr>

                                        <td class="px-6 py-8 text-sm text-slate-500" colspan="4">No accounts yet. Add your first credential above.</td>

                                    </tr>

                                <?php endif; ?>

                            </tbody>

                        </table>

                    </div>

                    <div class="md:hidden p-4 sm:p-5 space-y-4">

                        <?php if ($entries): ?>

                            <?php foreach ($entries as $entry): ?>

                                <?php $maskedPassword = str_repeat('*', 10); ?>

                                <div class="rounded-xl border border-border-dark bg-slate-50/60 dark:bg-background-dark/40 p-4 space-y-4 shadow-sm">
                                    <div class="flex items-start justify-between gap-3">
                                        <div>
                                            <p class="text-[11px] font-bold uppercase tracking-widest text-slate-500">Website</p>
                                            <p class="text-base font-bold text-slate-800 dark:text-slate-100"><?= htmlspecialchars((string) $entry['site_name'], ENT_QUOTES, 'UTF-8') ?></p>
                                        </div>
                                        <button class="p-2 rounded-lg text-slate-400 hover:text-primary hover:bg-primary/10 transition-all open-edit-account-modal" type="button" data-edit-account="true" data-entry-id="<?= (int) $entry['id'] ?>" data-site-name="<?= htmlspecialchars((string) $entry['site_name'], ENT_QUOTES, 'UTF-8') ?>" data-login-username="<?= htmlspecialchars((string) $entry['login_username'], ENT_QUOTES, 'UTF-8') ?>" aria-label="Edit account">
                                            <span class="material-symbols-outlined text-[20px]">edit</span>
                                        </button>
                                    </div>
                                    <div class="grid gap-3">
                                        <div>
                                            <p class="text-[11px] font-bold uppercase tracking-widest text-slate-500">Username</p>
                                            <p class="text-sm text-slate-600 dark:text-slate-300 break-all"><?= htmlspecialchars((string) $entry['login_username'], ENT_QUOTES, 'UTF-8') ?></p>
                                        </div>
                                        <div>
                                            <p class="text-[11px] font-bold uppercase tracking-widest text-slate-500">Password</p>
                                            <div class="flex items-center justify-between gap-2" data-password-container data-entry-id="<?= (int) $entry['id'] ?>">
                                                <p class="text-xs password-dots text-slate-400 font-mono" data-password-value data-password-mask="<?= htmlspecialchars($maskedPassword, ENT_QUOTES, 'UTF-8') ?>" data-visible="false"><?= htmlspecialchars($maskedPassword, ENT_QUOTES, 'UTF-8') ?></p>
                                                <button class="material-symbols-outlined text-[18px] text-slate-400 hover:text-primary transition-all password-toggle" type="button" data-entry-id="<?= (int) $entry['id'] ?>" aria-label="Show password">visibility</button>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                            <?php endforeach; ?>

                        <?php else: ?>

                            <div class="rounded-xl border border-border-dark bg-slate-50/60 dark:bg-background-dark/40 p-6 text-sm text-slate-500">No accounts yet. Add your first credential above.</div>

                        <?php endif; ?>

                    </div>

                </div>

                <div class="mt-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-slate-500 text-xs font-medium">

                    <div>Showing <?= htmlspecialchars((string) $totalEntries, ENT_QUOTES, 'UTF-8') ?> account<?= $totalEntries === 1 ? '' : 's' ?></div>

                    <div class="flex gap-2">
                        <?php $prevDisabled = $page <= 1; ?>
                        <?php $nextDisabled = $page >= $totalPages; ?>
                        <a class="px-4 py-1.5 bg-white dark:bg-surface-dark border border-border-dark rounded transition-colors font-bold <?= $prevDisabled ? 'pointer-events-none opacity-50' : 'hover:bg-slate-100 dark:hover:bg-background-dark' ?>" href="<?= $prevDisabled ? '#' : ('?page=' . ($page - 1)) ?>">Previous</a>
                        <a class="px-4 py-1.5 bg-white dark:bg-surface-dark border border-border-dark rounded transition-colors font-bold <?= $nextDisabled ? 'pointer-events-none opacity-50' : 'hover:bg-slate-100 dark:hover:bg-background-dark' ?>" href="<?= $nextDisabled ? '#' : ('?page=' . ($page + 1)) ?>">Next</a>
                    </div>

                </div>

            </div>

        </main>

    </div>

    <div class="<?= $addModalOpen ? '' : 'hidden' ?> fixed inset-0 z-40 bg-slate-950/60 backdrop-blur-sm" id="add-account-modal-overlay" aria-hidden="<?= $addModalOpen ? 'false' : 'true' ?>"></div>
    <div class="<?= $addModalOpen ? '' : 'hidden' ?> fixed inset-0 z-50 flex items-center justify-center p-4" id="add-account-modal" role="dialog" aria-modal="true" aria-labelledby="add-account-modal-title">
        <div class="w-full max-w-2xl bg-white dark:bg-surface-dark rounded-2xl border border-border-dark shadow-2xl">
            <div class="flex items-center justify-between px-6 py-4 border-b border-border-dark">
                <div>
                    <h3 class="text-lg font-bold" id="add-account-modal-title">Add Account</h3>
                    <p class="text-xs text-slate-500">Store a new credential in your vault.</p>
                </div>
                <button class="p-2 rounded-lg text-slate-400 hover:text-primary hover:bg-primary/10 transition-all" type="button" id="close-add-account-modal" aria-label="Close add account modal">
                    <span class="material-symbols-outlined text-[20px]">close</span>
                </button>
            </div>
            <div class="p-6">
                <?php if ($addSuccess): ?>
                    <div class="mb-4 rounded-lg border border-emerald-200 bg-emerald-50 text-emerald-700 text-xs font-semibold px-3 py-2">Account added successfully.</div>
                <?php endif; ?>
                <?php if ($addErrors): ?>
                    <div class="mb-4 rounded-lg border border-rose-200 bg-rose-50 text-rose-700 text-xs font-semibold px-3 py-2">
                        <ul class="list-disc pl-4 space-y-1">
                            <?php foreach ($addErrors as $error): ?>
                                <li><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endif; ?>
                <form class="grid grid-cols-1 lg:grid-cols-4 gap-4" method="post" action="">
                    <input type="hidden" name="action" value="add_account" />
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') ?>" />
                    <div class="flex flex-col gap-2 lg:col-span-2">
                        <label class="text-[11px] font-bold uppercase tracking-widest text-slate-500">Website</label>
                        <input class="form-input w-full rounded-lg border border-slate-200 dark:border-border-dark bg-slate-50 dark:bg-background-dark focus:border-primary focus:ring-2 focus:ring-primary/10 h-11 px-4 text-sm font-medium outline-none transition-all dark:text-white placeholder:text-slate-400" name="site_name" placeholder="Google Workspace" required="" type="text" autocomplete="organization" value="<?= htmlspecialchars($formData['site_name'], ENT_QUOTES, 'UTF-8') ?>" />
                    </div>
                    <div class="flex flex-col gap-2 lg:col-span-2">
                        <label class="text-[11px] font-bold uppercase tracking-widest text-slate-500">Username</label>
                        <input class="form-input w-full rounded-lg border border-slate-200 dark:border-border-dark bg-slate-50 dark:bg-background-dark focus:border-primary focus:ring-2 focus:ring-primary/10 h-11 px-4 text-sm font-medium outline-none transition-all dark:text-white placeholder:text-slate-400" name="login_username" placeholder="name@example.com" required="" type="text" autocomplete="username" value="<?= htmlspecialchars($formData['login_username'], ENT_QUOTES, 'UTF-8') ?>" />
                    </div>
                    <div class="flex flex-col gap-2 lg:col-span-3">
                        <label class="text-[11px] font-bold uppercase tracking-widest text-slate-500">Password</label>
                        <div class="relative">
                            <input class="form-input w-full rounded-lg border border-slate-200 dark:border-border-dark bg-slate-50 dark:bg-background-dark focus:border-primary focus:ring-2 focus:ring-primary/10 h-11 px-4 pr-11 text-sm font-medium outline-none transition-all dark:text-white placeholder:text-slate-400" id="add-login-password" name="login_password" placeholder="Enter password" required="" type="password" autocomplete="new-password" />
                            <button class="material-symbols-outlined absolute right-3 top-1/2 -translate-y-1/2 text-[18px] text-slate-400 hover:text-primary transition-colors toggle-input-password" type="button" data-target="add-login-password" aria-label="Show password">visibility</button>
                        </div>
                    </div>
                    <div class="flex justify-end items-end lg:col-span-1">
                        <button class="bg-primary text-white px-5 py-2 rounded-lg text-sm font-bold flex items-center gap-2 hover:brightness-110 active:scale-95 transition-all shadow-lg shadow-primary/20" type="submit">
                            <span class="material-symbols-outlined text-[18px]">save</span>
                            Save Account
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>


    <div class="<?= $editModalOpen ? '' : 'hidden' ?> fixed inset-0 z-40 bg-slate-950/60 backdrop-blur-sm" id="edit-account-modal-overlay" aria-hidden="<?= $editModalOpen ? 'false' : 'true' ?>"></div>
    <div class="<?= $editModalOpen ? '' : 'hidden' ?> fixed inset-0 z-50 flex items-center justify-center p-4" id="edit-account-modal" role="dialog" aria-modal="true" aria-labelledby="edit-account-modal-title">
        <div class="w-full max-w-2xl bg-white dark:bg-surface-dark rounded-2xl border border-border-dark shadow-2xl">
            <div class="flex items-center justify-between px-6 py-4 border-b border-border-dark">
                <div>
                    <h3 class="text-lg font-bold" id="edit-account-modal-title">Edit Account</h3>
                    <p class="text-xs text-slate-500">Update or remove this credential.</p>
                </div>
                <button class="p-2 rounded-lg text-slate-400 hover:text-primary hover:bg-primary/10 transition-all" type="button" id="close-edit-account-modal" aria-label="Close edit account modal">
                    <span class="material-symbols-outlined text-[20px]">close</span>
                </button>
            </div>
            <div class="p-6">
                <?php if ($editSuccess): ?>
                    <div class="mb-4 rounded-lg border border-emerald-200 bg-emerald-50 text-emerald-700 text-xs font-semibold px-3 py-2">Account updated successfully.</div>
                <?php endif; ?>
                <?php if ($editErrors): ?>
                    <div class="mb-4 rounded-lg border border-rose-200 bg-rose-50 text-rose-700 text-xs font-semibold px-3 py-2">
                        <ul class="list-disc pl-4 space-y-1">
                            <?php foreach ($editErrors as $error): ?>
                                <li><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endif; ?>
                <form class="grid grid-cols-1 lg:grid-cols-4 gap-4" method="post" action="" id="edit-account-form">
                    <input type="hidden" name="action" value="update_account" />
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') ?>" />
                    <input type="hidden" name="entry_id" id="edit-entry-id" value="<?= htmlspecialchars($editFormData['entry_id'], ENT_QUOTES, 'UTF-8') ?>" />
                    <div class="flex flex-col gap-2 lg:col-span-2">
                        <label class="text-[11px] font-bold uppercase tracking-widest text-slate-500">Website</label>
                        <input class="form-input w-full rounded-lg border border-slate-200 dark:border-border-dark bg-slate-50 dark:bg-background-dark focus:border-primary focus:ring-2 focus:ring-primary/10 h-11 px-4 text-sm font-medium outline-none transition-all dark:text-white placeholder:text-slate-400" id="edit-site-name" name="site_name" placeholder="Google Workspace" required="" type="text" autocomplete="organization" value="<?= htmlspecialchars($editFormData['site_name'], ENT_QUOTES, 'UTF-8') ?>" />
                    </div>
                    <div class="flex flex-col gap-2 lg:col-span-2">
                        <label class="text-[11px] font-bold uppercase tracking-widest text-slate-500">Username</label>
                        <input class="form-input w-full rounded-lg border border-slate-200 dark:border-border-dark bg-slate-50 dark:bg-background-dark focus:border-primary focus:ring-2 focus:ring-primary/10 h-11 px-4 text-sm font-medium outline-none transition-all dark:text-white placeholder:text-slate-400" id="edit-login-username" name="login_username" placeholder="name@example.com" required="" type="text" autocomplete="username" value="<?= htmlspecialchars($editFormData['login_username'], ENT_QUOTES, 'UTF-8') ?>" />
                    </div>
                    <div class="flex flex-col gap-2 lg:col-span-3">
                        <label class="text-[11px] font-bold uppercase tracking-widest text-slate-500">Password</label>
                        <div class="relative">
                        <input class="form-input w-full rounded-lg border border-slate-200 dark:border-border-dark bg-slate-50 dark:bg-background-dark focus:border-primary focus:ring-2 focus:ring-primary/10 h-11 px-4 pr-11 text-sm font-medium outline-none transition-all dark:text-white placeholder:text-slate-400" id="edit-login-password" name="login_password" placeholder="Leave blank to keep current password" type="password" autocomplete="new-password" data-fetch-password="true" />
                            <button class="material-symbols-outlined absolute right-3 top-1/2 -translate-y-1/2 text-[18px] text-slate-400 hover:text-primary transition-colors toggle-input-password" type="button" data-target="edit-login-password" aria-label="Show password">visibility</button>
                        </div>
                    </div>
                    <div class="flex justify-end items-end lg:col-span-1">
                        <button class="bg-primary text-white px-5 py-2 rounded-lg text-sm font-bold flex items-center gap-2 hover:brightness-110 active:scale-95 transition-all shadow-lg shadow-primary/20" type="submit">
                            <span class="material-symbols-outlined text-[18px]">save</span>
                            Save Changes
                        </button>
                    </div>
                </form>
                <form class="mt-6 pt-4 border-t border-border-dark flex items-center justify-between" method="post" action="">
                    <input type="hidden" name="action" value="delete_account" />
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') ?>" />
                    <input type="hidden" name="entry_id" id="delete-entry-id" value="<?= htmlspecialchars($editFormData['entry_id'], ENT_QUOTES, 'UTF-8') ?>" />
                    <p class="text-xs text-slate-500">Remove this account from your vault.</p>
                    <button class="px-4 py-2 rounded-lg text-xs font-bold text-rose-600 border border-rose-200 hover:bg-rose-50 transition-colors" type="submit" onclick="return confirm('Delete this account?');">Delete Account</button>
                </form>
            </div>
        </div>
    </div>

    <script>
        (function() {
            const csrfToken = "<?= htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') ?>";
            const addOpenButton = document.getElementById('open-add-account-modal');
            const addCloseButton = document.getElementById('close-add-account-modal');
            const addModal = document.getElementById('add-account-modal');
            const addOverlay = document.getElementById('add-account-modal-overlay');

            const editModal = document.getElementById('edit-account-modal');
            const editOverlay = document.getElementById('edit-account-modal-overlay');
            const editCloseButton = document.getElementById('close-edit-account-modal');
            const editIdInput = document.getElementById('edit-entry-id');
            const deleteIdInput = document.getElementById('delete-entry-id');
            const editSiteInput = document.getElementById('edit-site-name');
            const editUsernameInput = document.getElementById('edit-login-username');
            const editPasswordInput = document.getElementById('edit-login-password');
            const themeToggles = document.querySelectorAll('[data-theme-toggle]');

            function getThemePreference() {
                const stored = localStorage.getItem('theme');
                if (stored === 'dark' || stored === 'light') {
                    return stored;
                }
                return 'dark';
            }

            function applyTheme(theme) {
                const isDark = theme === 'dark';
                document.documentElement.classList.toggle('dark', isDark);
                themeToggles.forEach(function(toggle) {
                    const icon = toggle.querySelector('[data-theme-icon]');
                    if (icon) {
                        icon.textContent = isDark ? 'light_mode' : 'dark_mode';
                    }
                    toggle.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
                });
            }

            applyTheme(getThemePreference());
            themeToggles.forEach(function(toggle) {
                toggle.addEventListener('click', function() {
                    const nextTheme = document.documentElement.classList.contains('dark') ? 'light' : 'dark';
                    localStorage.setItem('theme', nextTheme);
                    applyTheme(nextTheme);
                });
            });

            function openModal(modal, overlay) {
                if (!modal || !overlay) {
                    return;
                }

                modal.classList.remove('hidden');
                overlay.classList.remove('hidden');
                overlay.setAttribute('aria-hidden', 'false');
            }

            function closeModal(modal, overlay) {
                if (!modal || !overlay) {
                    return;
                }

                modal.classList.add('hidden');
                overlay.classList.add('hidden');
                overlay.setAttribute('aria-hidden', 'true');
            }

            async function fetchPassword(entryId) {
                const response = await fetch('../api/vault-password.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ entry_id: entryId })
                });

                if (!response.ok) {
                    return null;
                }

                const data = await response.json();
                return data && data.password ? data.password : null;
            }

            if (addOpenButton) {
                addOpenButton.addEventListener('click', function() {
                    openModal(addModal, addOverlay);
                });
            }

            if (addCloseButton) {
                addCloseButton.addEventListener('click', function() {
                    closeModal(addModal, addOverlay);
                });
            }

            if (addOverlay) {
                addOverlay.addEventListener('click', function() {
                    closeModal(addModal, addOverlay);
                });
            }

            if (editCloseButton) {
                editCloseButton.addEventListener('click', function() {
                    closeModal(editModal, editOverlay);
                });
            }

            if (editOverlay) {
                editOverlay.addEventListener('click', function() {
                    closeModal(editModal, editOverlay);
                });
            }

            document.querySelectorAll('[data-edit-account]').forEach(function(button) {
                button.addEventListener('click', function() {
                    const id = button.getAttribute('data-entry-id') || '';
                    const siteName = button.getAttribute('data-site-name') || '';
                    const loginUsername = button.getAttribute('data-login-username') || '';

                    if (editIdInput) {
                        editIdInput.value = id;
                    }

                    if (deleteIdInput) {
                        deleteIdInput.value = id;
                    }

                    if (editSiteInput) {
                        editSiteInput.value = siteName;
                    }

                    if (editUsernameInput) {
                        editUsernameInput.value = loginUsername;
                    }

                    if (editPasswordInput) {
                        editPasswordInput.value = '';
                    }

                    openModal(editModal, editOverlay);
                });
            });

            document.querySelectorAll('.password-toggle').forEach(function(button) {
                button.addEventListener('click', async function() {
                    const container = button.closest('[data-password-container]');
                    if (!container) {
                        return;
                    }

                    const valueEl = container.querySelector('[data-password-value]');
                    if (!valueEl) {
                        return;
                    }

                    const isVisible = valueEl.getAttribute('data-visible') === 'true';
                    if (isVisible) {
                        valueEl.textContent = valueEl.getAttribute('data-password-mask') || '';
                        valueEl.setAttribute('data-visible', 'false');
                        button.textContent = 'visibility';
                        button.setAttribute('aria-label', 'Show password');
                        return;
                    }

                    const entryId = button.getAttribute('data-entry-id') || container.getAttribute('data-entry-id');
                    if (!entryId) {
                        return;
                    }

                    let password = valueEl.getAttribute('data-password') || '';
                    if (!password) {
                        password = await fetchPassword(entryId);
                        if (!password) {
                            return;
                        }
                        valueEl.setAttribute('data-password', password);
                    }

                    valueEl.textContent = password;
                    valueEl.setAttribute('data-visible', 'true');
                    button.textContent = 'visibility_off';
                    button.setAttribute('aria-label', 'Hide password');
                });
            });

            document.querySelectorAll('.toggle-input-password').forEach(function(button) {
                const targetId = button.getAttribute('data-target');
                if (!targetId) {
                    return;
                }

                const input = document.getElementById(targetId);
                if (!input) {
                    return;
                }

                button.addEventListener('click', async function() {
                    const isPassword = input.getAttribute('type') === 'password';
                    if (isPassword && input.value === '' && input.getAttribute('data-fetch-password') === 'true') {
                        const entryId = editIdInput ? editIdInput.value : '';
                        if (entryId) {
                            const fetched = await fetchPassword(entryId);
                            if (fetched) {
                                input.value = fetched;
                            }
                        }
                    }

                    const nextIsPassword = input.getAttribute('type') === 'password';
                    input.setAttribute('type', nextIsPassword ? 'text' : 'password');
                    button.textContent = nextIsPassword ? 'visibility_off' : 'visibility';
                    button.setAttribute('aria-label', nextIsPassword ? 'Hide password' : 'Show password');
                });
            });
        })();
    </script>

</body>

</html>

<?php
session_start();

// SQLite3 Database Initialization
$db = new SQLite3('../databases/lightseagreen.db'); // Adjust path as needed

// Create necessary tables if they don't exist
$db->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
);");

$db->exec("CREATE TABLE IF NOT EXISTS spreadsheets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);");

$db->exec("CREATE TABLE IF NOT EXISTS sheets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    spreadsheet_id INTEGER,
    name TEXT,
    UNIQUE(spreadsheet_id, name),
    FOREIGN KEY(spreadsheet_id) REFERENCES spreadsheets(id)
);");

$db->exec("CREATE TABLE IF NOT EXISTS cells (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sheet_id INTEGER,
    row INTEGER,
    col INTEGER,
    value TEXT,
    UNIQUE(sheet_id, row, col),
    FOREIGN KEY(sheet_id) REFERENCES sheets(id)
);");

// Helper function for JSON response
function response($status, $data = []) {
    header('Content-Type: application/json');
    echo json_encode(['status' => $status, 'data' => $data]);
    exit;
}

// Handle POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    try {
        switch ($_POST['action']) {
            case 'register':
                $username = trim($_POST['username']);
                $password = trim($_POST['password']);

                if (empty($username) || empty($password)) {
                    response('error', 'Username and password cannot be empty.');
                }

                $hashed_password = password_hash($password, PASSWORD_BCRYPT);

                $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
                $stmt->bindValue(1, $username, SQLITE3_TEXT);
                $stmt->bindValue(2, $hashed_password, SQLITE3_TEXT);
                $stmt->execute();

                response('success', 'Registration successful.');
                break;

            case 'login':
                $username = trim($_POST['username']);
                $password = trim($_POST['password']);

                if (empty($username) || empty($password)) {
                    response('error', 'Username and password cannot be empty.');
                }

                $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
                $stmt->bindValue(1, $username, SQLITE3_TEXT);
                $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

                if ($result && password_verify($password, $result['password'])) {
                    $_SESSION['user_id'] = $result['id'];
                    response('success', 'Login successful.');
                } else {
                    response('error', 'Invalid credentials.');
                }
                break;

            case 'create_spreadsheet':
                if (!isset($_SESSION['user_id'])) response('error', 'Not logged in.');

                $name = trim($_POST['name']);
                if (empty($name)) {
                    response('error', 'Spreadsheet name cannot be empty.');
                }

                $stmt = $db->prepare("INSERT INTO spreadsheets (user_id, name) VALUES (?, ?)");
                $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
                $stmt->bindValue(2, $name, SQLITE3_TEXT);
                $stmt->execute();
                $spreadsheet_id = $db->lastInsertRowID();

                // Create a default sheet named "Sheet1"
                $stmt = $db->prepare("INSERT INTO sheets (spreadsheet_id, name) VALUES (?, 'Sheet1')");
                $stmt->bindValue(1, $spreadsheet_id, SQLITE3_INTEGER);
                $stmt->execute();

                response('success', 'Spreadsheet created successfully.');
                break;

            case 'delete_spreadsheet':
                if (!isset($_SESSION['user_id'])) response('error', 'Not logged in.');

                $spreadsheet_id = intval($_POST['spreadsheet_id']);
                if ($spreadsheet_id <= 0) {
                    response('error', 'Invalid spreadsheet ID.');
                }

                // Verify ownership
                $stmt = $db->prepare("SELECT * FROM spreadsheets WHERE id = ? AND user_id = ?");
                $stmt->bindValue(1, $spreadsheet_id, SQLITE3_INTEGER);
                $stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
                $spreadsheet = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

                if (!$spreadsheet) {
                    response('error', 'Spreadsheet not found or access denied.');
                }

                // Delete associated cells
                $stmt = $db->prepare("SELECT id FROM sheets WHERE spreadsheet_id = ?");
                $stmt->bindValue(1, $spreadsheet_id, SQLITE3_INTEGER);
                $sheets_result = $stmt->execute();

                while ($sheet = $sheets_result->fetchArray(SQLITE3_ASSOC)) {
                    $sheet_id = $sheet['id'];
                    $db->exec("DELETE FROM cells WHERE sheet_id = $sheet_id");
                }

                // Delete sheets
                $stmt = $db->prepare("DELETE FROM sheets WHERE spreadsheet_id = ?");
                $stmt->bindValue(1, $spreadsheet_id, SQLITE3_INTEGER);
                $stmt->execute();

                // Delete spreadsheet
                $stmt = $db->prepare("DELETE FROM spreadsheets WHERE id = ?");
                $stmt->bindValue(1, $spreadsheet_id, SQLITE3_INTEGER);
                $stmt->execute();

                response('success', 'Spreadsheet deleted successfully.');
                break;

            case 'rename_spreadsheet':
                if (!isset($_SESSION['user_id'])) response('error', 'Not logged in.');

                $spreadsheet_id = intval($_POST['spreadsheet_id']);
                $new_name = trim($_POST['new_name']);

                if ($spreadsheet_id <= 0 || empty($new_name)) {
                    response('error', 'Invalid parameters.');
                }

                // Verify ownership
                $stmt = $db->prepare("SELECT * FROM spreadsheets WHERE id = ? AND user_id = ?");
                $stmt->bindValue(1, $spreadsheet_id, SQLITE3_INTEGER);
                $stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
                $spreadsheet = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

                if (!$spreadsheet) {
                    response('error', 'Spreadsheet not found or access denied.');
                }

                // Update name
                $stmt = $db->prepare("UPDATE spreadsheets SET name = ? WHERE id = ?");
                $stmt->bindValue(1, $new_name, SQLITE3_TEXT);
                $stmt->bindValue(2, $spreadsheet_id, SQLITE3_INTEGER);
                $stmt->execute();

                response('success', 'Spreadsheet renamed successfully.');
                break;

            case 'create_sheet':
                if (!isset($_SESSION['user_id'])) response('error', 'Not logged in.');

                $spreadsheet_id = intval($_POST['spreadsheet_id']);
                $sheet_name = trim($_POST['sheet_name']);

                if ($spreadsheet_id <= 0 || empty($sheet_name)) {
                    response('error', 'Invalid parameters.');
                }

                // Verify ownership
                $stmt = $db->prepare("SELECT * FROM spreadsheets WHERE id = ? AND user_id = ?");
                $stmt->bindValue(1, $spreadsheet_id, SQLITE3_INTEGER);
                $stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
                $spreadsheet = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

                if (!$spreadsheet) {
                    response('error', 'Spreadsheet not found or access denied.');
                }

                // Insert new sheet
                $stmt = $db->prepare("INSERT INTO sheets (spreadsheet_id, name) VALUES (?, ?)");
                $stmt->bindValue(1, $spreadsheet_id, SQLITE3_INTEGER);
                $stmt->bindValue(2, $sheet_name, SQLITE3_TEXT);
                $stmt->execute();

                response('success', 'Sheet created successfully.');
                break;

            case 'delete_sheet':
                if (!isset($_SESSION['user_id'])) response('error', 'Not logged in.');

                $sheet_id = intval($_POST['sheet_id']);
                if ($sheet_id <= 0) {
                    response('error', 'Invalid sheet ID.');
                }

                // Verify ownership
                $stmt = $db->prepare("SELECT spreadsheets.user_id FROM sheets 
                                      JOIN spreadsheets ON sheets.spreadsheet_id = spreadsheets.id 
                                      WHERE sheets.id = ?");
                $stmt->bindValue(1, $sheet_id, SQLITE3_INTEGER);
                $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

                if (!$result || $result['user_id'] !== $_SESSION['user_id']) {
                    response('error', 'Sheet not found or access denied.');
                }

                // Delete associated cells
                $stmt = $db->prepare("DELETE FROM cells WHERE sheet_id = ?");
                $stmt->bindValue(1, $sheet_id, SQLITE3_INTEGER);
                $stmt->execute();

                // Delete sheet
                $stmt = $db->prepare("DELETE FROM sheets WHERE id = ?");
                $stmt->bindValue(1, $sheet_id, SQLITE3_INTEGER);
                $stmt->execute();

                response('success', 'Sheet deleted successfully.');
                break;

            case 'rename_sheet':
                if (!isset($_SESSION['user_id'])) response('error', 'Not logged in.');

                $sheet_id = intval($_POST['sheet_id']);
                $new_name = trim($_POST['new_name']);

                if ($sheet_id <= 0 || empty($new_name)) {
                    response('error', 'Invalid parameters.');
                }

                // Verify ownership
                $stmt = $db->prepare("SELECT spreadsheets.user_id FROM sheets 
                                      JOIN spreadsheets ON sheets.spreadsheet_id = spreadsheets.id 
                                      WHERE sheets.id = ?");
                $stmt->bindValue(1, $sheet_id, SQLITE3_INTEGER);
                $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

                if (!$result || $result['user_id'] !== $_SESSION['user_id']) {
                    response('error', 'Sheet not found or access denied.');
                }

                // Update sheet name
                $stmt = $db->prepare("UPDATE sheets SET name = ? WHERE id = ?");
                $stmt->bindValue(1, $new_name, SQLITE3_TEXT);
                $stmt->bindValue(2, $sheet_id, SQLITE3_INTEGER);
                $stmt->execute();

                response('success', 'Sheet renamed successfully.');
                break;

            case 'update_cell':
                if (!isset($_SESSION['user_id'])) response('error', 'Not logged in.');

                $sheet_id = intval($_POST['sheet_id']);
                $row = intval($_POST['row']);
                $col = intval($_POST['col']);
                $value = trim($_POST['value']);

                if ($sheet_id <= 0 || $row <= 0 || $col < 0) {
                    response('error', 'Invalid parameters.');
                }

                // Verify ownership
                $stmt = $db->prepare("SELECT spreadsheets.user_id FROM sheets 
                                      JOIN spreadsheets ON sheets.spreadsheet_id = spreadsheets.id 
                                      WHERE sheets.id = ?");
                $stmt->bindValue(1, $sheet_id, SQLITE3_INTEGER);
                $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

                if (!$result || $result['user_id'] !== $_SESSION['user_id']) {
                    response('error', 'Sheet not found or access denied.');
                }

                // Upsert cell
                $stmt = $db->prepare("
                    INSERT INTO cells (sheet_id, row, col, value) 
                    VALUES (?, ?, ?, ?) 
                    ON CONFLICT(sheet_id, row, col) 
                    DO UPDATE SET value=excluded.value
                ");
                $stmt->bindValue(1, $sheet_id, SQLITE3_INTEGER);
                $stmt->bindValue(2, $row, SQLITE3_INTEGER);
                $stmt->bindValue(3, $col, SQLITE3_INTEGER);
                $stmt->bindValue(4, $value, SQLITE3_TEXT);
                $stmt->execute();

                response('success', 'Cell updated successfully.');
                break;

            case 'fetch_spreadsheet':
                if (!isset($_SESSION['user_id'])) response('error', 'Not logged in.');

                $spreadsheet_id = intval($_POST['spreadsheet_id']);
                $sheet_id = intval($_POST['sheet_id']);

                if ($spreadsheet_id <= 0 || $sheet_id <= 0) {
                    response('error', 'Invalid parameters.');
                }

                // Verify ownership
                $stmt = $db->prepare("SELECT spreadsheets.user_id FROM sheets 
                                      JOIN spreadsheets ON sheets.spreadsheet_id = spreadsheets.id 
                                      WHERE sheets.id = ? AND spreadsheets.id = ?");
                $stmt->bindValue(1, $sheet_id, SQLITE3_INTEGER);
                $stmt->bindValue(2, $spreadsheet_id, SQLITE3_INTEGER);
                $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

                if (!$result || $result['user_id'] !== $_SESSION['user_id']) {
                    response('error', 'Spreadsheet or sheet not found or access denied.');
                }

                // Fetch cells
                $stmt = $db->prepare("SELECT row, col, value FROM cells WHERE sheet_id = ?");
                $stmt->bindValue(1, $sheet_id, SQLITE3_INTEGER);
                $cells_result = $stmt->execute();

                $cells = [];
                while ($cell = $cells_result->fetchArray(SQLITE3_ASSOC)) {
                    $cells[] = $cell;
                }

                response('success', $cells);
                break;

            case 'list_spreadsheets':
                if (!isset($_SESSION['user_id'])) response('error', 'Not logged in.');

                $stmt = $db->prepare("SELECT * FROM spreadsheets WHERE user_id = ?");
                $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
                $spreadsheets_result = $stmt->execute();

                $spreadsheets = [];
                while ($spreadsheet = $spreadsheets_result->fetchArray(SQLITE3_ASSOC)) {
                    $spreadsheets[] = $spreadsheet;
                }

                response('success', $spreadsheets);
                break;

            case 'list_sheets':
                if (!isset($_SESSION['user_id'])) response('error', 'Not logged in.');

                $spreadsheet_id = intval($_POST['spreadsheet_id']);
                if ($spreadsheet_id <= 0) {
                    response('error', 'Invalid spreadsheet ID.');
                }

                // Verify ownership
                $stmt = $db->prepare("SELECT * FROM spreadsheets WHERE id = ? AND user_id = ?");
                $stmt->bindValue(1, $spreadsheet_id, SQLITE3_INTEGER);
                $stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
                $spreadsheet = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

                if (!$spreadsheet) {
                    response('error', 'Spreadsheet not found or access denied.');
                }

                // Fetch sheets
                $stmt = $db->prepare("SELECT * FROM sheets WHERE spreadsheet_id = ?");
                $stmt->bindValue(1, $spreadsheet_id, SQLITE3_INTEGER);
                $sheets_result = $stmt->execute();

                $sheets = [];
                while ($sheet = $sheets_result->fetchArray(SQLITE3_ASSOC)) {
                    $sheets[] = $sheet;
                }

                response('success', $sheets);
                break;

            case 'logout':
                session_unset();
                session_destroy();
                response('success', 'Logged out successfully.');
                break;

            case 'check_session':
                if (isset($_SESSION['user_id'])) {
                    response('success', 'Session active.');
                } else {
                    response('error', 'No active session.');
                }
                break;

            default:
                response('error', 'Unknown action.');
        }
    } catch (Exception $e) {
        error_log($e->getMessage());
        response('error', 'An error occurred. Please try again later.');
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>jocarsa | lightseagreen</title>
  <link rel='icon' type='image/svg+xml' href='https://jocarsa.com/static/logo/jocarsa%20|%20lightseagreen.svg' />
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="styles.css">
</head>
<body>

<header>
  <h1>
    <img src="https://jocarsa.com/static/logo/jocarsa%20|%20white.svg" alt="Logo"/>
    jocarsa | lightseagreen
  </h1>
  <div>
    <button onclick="logout()">Logout</button>
  </div>
</header>

<main>
  <div id="aplicacion">
    <!-- Left Pane -->
    <div id="left">
      <div>
        <h2>Create Spreadsheet</h2>
        <input type="text" id="spreadsheet-name" placeholder="Spreadsheet Name">
        <button onclick="createSpreadsheet(document.getElementById('spreadsheet-name').value)">
          Create
        </button>
      </div>
      <div>
        <h2>Your Spreadsheets</h2>
        <ul id="spreadsheet-list"></ul>
      </div>
    </div>

    <!-- Right Pane -->
    <div id="right">
      <!-- Sheets Tabs -->
      <div id="sheets-tabs" style="margin-bottom: 10px;">
        <button onclick="addSheet()">+ Add Sheet</button>
        <div id="tabs-container" style="display: inline-block; margin-left: 10px;"></div>
      </div>

      <!-- Formula Bar -->
      <div style="margin-bottom: 10px;">
        <input
          type="text"
          id="formula-bar"
          style="width: 98%; padding: 5px; font-size: 14px;"
          placeholder="Formula bar (e.g. =A1 + B2)"
          disabled
        >
      </div>
      <div id="spreadsheet-container"></div>
      <button onclick="addRow()" style="margin-top: 10px;">+ Add Row</button>
    </div>
  </div>

  <!-- Login/Signup Section -->
  <div id="loginsignup">
    <div>
      <h2>Login</h2>
      <input type="text" id="login-username" placeholder="Username">
      <input type="password" id="login-password" placeholder="Password">
      <button onclick="login(
        document.getElementById('login-username').value,
        document.getElementById('login-password').value
      )">Login</button>
    </div>
    <div>
      <h2>Register</h2>
      <input type="text" id="register-username" placeholder="Username">
      <input type="password" id="register-password" placeholder="Password">
      <button onclick="register(
        document.getElementById('register-username').value,
        document.getElementById('register-password').value
      )">Register</button>
    </div>
  </div>
</main>

<!-- Include Math.js Library for Safe Formula Evaluation -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/mathjs/11.8.0/math.min.js"></script>

<script>
/**
 * Call the back-end (this same file) using POST + form data.
 */
async function api(action, data) {
  const response = await fetch('', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ action, ...data })
  });
  return await response.json();
}

// -------------------------------------------------------------------
// 1. Formula Evaluation Logic
// -------------------------------------------------------------------
/**
 * Evaluate a formula that may contain cell references (e.g., =A1 + B2)
 * @param {string} formula - The formula string starting with '='
 * @param {Set} visited - A set to keep track of visited cells for circular reference detection
 * @returns {number|string} - The result of the evaluation or an error indicator
 */
function evaluateFormula(formula, visited = new Set()) {
    // Remove leading '='
    const expr = formula.substring(1);

    // Regular expression to match cell references (e.g., A1, B2, AA10)
    const cellRefRegex = /\b([A-Z]+)(\d+)\b/g;

    // Function to convert column letters to zero-based index
    function colLettersToIndex(letters) {
        let index = 0;
        for (let i = 0; i < letters.length; i++) {
            index *= 26;
            index += letters.charCodeAt(i) - 64; // 'A' is 65 in ASCII
        }
        return index - 1;
    }

    // Replace cell references with their actual values
    const exprWithValues = expr.replace(cellRefRegex, (match, colLetters, rowNumber) => {
        const cellId = `${match.toUpperCase()}`;
        if (visited.has(cellId)) {
            // Circular reference detected
            throw new Error('Circular Reference');
        }
        visited.add(cellId);

        const col = colLettersToIndex(colLetters.toUpperCase());
        const row = parseInt(rowNumber, 10);
        const cell = document.querySelector(`input[data-row="${row}"][data-col="${col}"]`);
        if (cell) {
            const rawValue = cell.dataset.rawValue || '';
            let computedValue = computeCellValue(rawValue);
            if (typeof computedValue === 'string' && computedValue.startsWith('=')) {
                // Recursively evaluate nested formulas
                computedValue = evaluateFormula(computedValue, visited);
            }
            const value = isNaN(computedValue) ? 0 : computedValue;
            visited.delete(cellId);
            return value;
        } else {
            visited.delete(cellId);
            return 0; // Default value if cell not found
        }
    });

    try {
        // Use Math.js for safe evaluation
        return math.evaluate(exprWithValues);
    } catch (e) {
        return '#ERR';
    }
}

function computeCellValue(rawValue) {
    if (typeof rawValue === 'string' && rawValue.trim().startsWith('=')) {
        try {
            return evaluateFormula(rawValue.trim());
        } catch (e) {
            return '#CIRC'; // Indicate circular reference
        }
    }
    return rawValue;
}

// -------------------------------------------------------------------
// 2. Global State
// -------------------------------------------------------------------
let currentlyEditingCell = null;   // The cell currently in focus
let activeSpreadsheetId = null;    // The currently open spreadsheet
let activeSheetId = null;          // The currently active sheet

// Dependency graph to track which cells depend on which
const dependencies = {};

// -------------------------------------------------------------------
// 3. Cell Event Handlers
// -------------------------------------------------------------------
function attachInputEvents(input, sheetId, row, col) {
    input.addEventListener('focus', () => {
        currentlyEditingCell = input;
        document.getElementById('formula-bar').disabled = false;
        // Show raw value in formula bar
        document.getElementById('formula-bar').value = input.dataset.rawValue || '';
    });

    // If user changes cell directly
    input.addEventListener('change', () => {
        const newRawValue = input.value;
        updateCell(activeSpreadsheetId, activeSheetId, row, col, newRawValue)
            .then(response => {
                if (response.status === 'success') {
                    input.dataset.rawValue = newRawValue;
                    // Update dependencies
                    const cellId = input.dataset.cell;
                    updateDependencies(cellId, newRawValue);
                    // Show computed result if formula, otherwise raw
                    input.value = computeCellValue(newRawValue);
                    // Recalculate dependent cells
                    recalculateDependencies(cellId);
                } else {
                    alert('Error updating cell.');
                }
            });
    });
}

function setupFormulaBarListener() {
    const formulaBar = document.getElementById('formula-bar');

    // If user presses Enter in the formula bar
    formulaBar.addEventListener('keyup', (event) => {
        if (event.key === 'Enter') {
            commitFormulaBarChange();
        }
    });

    // If user clicks away from the formula bar
    formulaBar.addEventListener('blur', () => {
        commitFormulaBarChange();
    });
}

function commitFormulaBarChange() {
    if (!currentlyEditingCell) return;

    const formulaBar = document.getElementById('formula-bar');
    const newRawValue = formulaBar.value;

    updateCell(
        activeSpreadsheetId,
        activeSheetId,
        currentlyEditingCell.dataset.row,
        currentlyEditingCell.dataset.col,
        newRawValue
    ).then(response => {
        if (response.status === 'success') {
            currentlyEditingCell.dataset.rawValue = newRawValue;
            // Update dependencies
            const cellId = currentlyEditingCell.dataset.cell;
            updateDependencies(cellId, newRawValue);
            currentlyEditingCell.value = computeCellValue(newRawValue);
            // Recalculate dependent cells
            recalculateDependencies(cellId);
        } else {
            alert('Error updating cell.');
        }
    });
}

// -------------------------------------------------------------------
// 4. Dependency Management
// -------------------------------------------------------------------
/**
 * Update the dependency graph for a given cell based on its formula.
 * @param {string} cell - The cell identifier (e.g., 'A1')
 * @param {string} formula - The raw value of the cell
 */
function updateDependencies(cell, formula) {
    // Remove existing dependencies for this cell
    if (dependencies[cell]) {
        delete dependencies[cell];
    }

    // Initialize dependencies for this cell
    dependencies[cell] = [];

    if (typeof formula === 'string' && formula.trim().startsWith('=')) {
        // Regular expression to match cell references
        const cellRefRegex = /\b([A-Z]+)(\d+)\b/g;
        let match;
        while ((match = cellRefRegex.exec(formula)) !== null) {
            dependencies[cell].push(match[0].toUpperCase());
        }
    }
}

/**
 * Recalculate all cells that depend on the given cell.
 * @param {string} cell - The cell identifier (e.g., 'A1')
 */
function recalculateDependencies(cell) {
    for (const [key, deps] of Object.entries(dependencies)) {
        if (deps.includes(cell)) {
            const depInput = document.querySelector(`input[data-cell="${key}"]`);
            if (depInput) {
                const newValue = computeCellValue(depInput.dataset.rawValue);
                depInput.value = newValue;
                recalculateDependencies(key); // Recursively update further dependencies
            }
        }
    }
}

// -------------------------------------------------------------------
// 5. API Calls and Spreadsheet Management
// -------------------------------------------------------------------
function updateCell(spreadsheetId, sheetId, row, col, value) {
    return api('update_cell', {
        spreadsheet_id: spreadsheetId,
        sheet_id: sheetId,
        row: row,
        col: col,
        value: value
    });
}

function createSpreadsheet(name) {
    if (!name.trim()) {
        alert('Spreadsheet name cannot be empty.');
        return;
    }
    api('create_spreadsheet', { name }).then(response => {
        if (response.status === 'success') {
            alert('Spreadsheet created!');
            listSpreadsheets();
            document.getElementById('spreadsheet-name').value = ''; // Clear input
        } else {
            alert(response.data);
        }
    });
}

function fetchSpreadsheet(spreadsheetId) {
    activeSpreadsheetId = spreadsheetId;
    activeSheetId = null; // Reset active sheet when switching spreadsheets
    api('list_sheets', { spreadsheet_id: spreadsheetId }).then(response => {
        if (response.status === 'success') {
            const sheets = response.data;
            if (sheets.length === 0) {
                // If no sheets exist, create a default one
                createSheet(spreadsheetId, 'Sheet1').then(() => {
                    listSheets(spreadsheetId);
                });
            } else {
                listSheets(spreadsheetId);
            }
        } else {
            alert(response.data);
        }
    });
}

function listSpreadsheets() {
    api('list_spreadsheets', {}).then(response => {
        if (response.status === 'success') {
            const list = document.getElementById('spreadsheet-list');
            list.innerHTML = ''; // Clear old list

            response.data.forEach(sheet => {
                const item = document.createElement('li');
                item.textContent = sheet.name;
                item.style.cursor = 'pointer';
                item.onclick = () => fetchSpreadsheet(sheet.id);

                // Add rename and delete buttons
                const renameBtn = document.createElement('button');
                renameBtn.textContent = 'Rename';
                renameBtn.style.marginLeft = '10px';
                renameBtn.onclick = (e) => {
                    e.stopPropagation();
                    const newName = prompt('Enter new spreadsheet name:', sheet.name);
                    if (newName && newName.trim()) {
                        renameSpreadsheet(sheet.id, newName.trim());
                    }
                };

                const deleteBtn = document.createElement('button');
                deleteBtn.textContent = 'Delete';
                deleteBtn.style.marginLeft = '5px';
                deleteBtn.onclick = (e) => {
                    e.stopPropagation();
                    if (confirm(`Are you sure you want to delete "${sheet.name}"?`)) {
                        deleteSpreadsheet(sheet.id);
                    }
                };

                item.appendChild(renameBtn);
                item.appendChild(deleteBtn);
                list.appendChild(item);
            });
        } else {
            alert(response.data);
        }
    });
}

function listSheets(spreadsheetId) {
    api('list_sheets', { spreadsheet_id: spreadsheetId }).then(response => {
        if (response.status === 'success') {
            const sheets = response.data;
            const tabsContainer = document.getElementById('tabs-container');
            tabsContainer.innerHTML = ''; // Clear existing tabs

            sheets.forEach(sheet => {
                const tab = document.createElement('button');
                tab.textContent = sheet.name;
                tab.classList.add('sheet-tab');
                tab.dataset.sheetId = sheet.id; // Add data-sheet-id attribute
                if (sheet.id === activeSheetId) {
                    tab.classList.add('active-tab');
                }
                tab.onclick = () => {
                    setActiveSheet(sheet.id);
                };

                // Add rename and delete buttons to each tab
                const renameBtn = document.createElement('button');
                renameBtn.textContent = '✏️';
                renameBtn.style.marginLeft = '5px';
                renameBtn.style.cursor = 'pointer';
                renameBtn.onclick = (e) => {
                    e.stopPropagation();
                    const newName = prompt('Enter new sheet name:', sheet.name);
                    if (newName && newName.trim()) {
                        renameSheet(sheet.id, newName.trim());
                    }
                };

                const deleteBtn = document.createElement('button');
                deleteBtn.textContent = '🗑️';
                deleteBtn.style.marginLeft = '2px';
                deleteBtn.style.cursor = 'pointer';
                deleteBtn.onclick = (e) => {
                    e.stopPropagation();
                    if (confirm(`Are you sure you want to delete sheet "${sheet.name}"?`)) {
                        deleteSheet(sheet.id);
                    }
                };

                tab.appendChild(renameBtn);
                tab.appendChild(deleteBtn);
                tabsContainer.appendChild(tab);
            });

            // Activate the first sheet by default if none is active
            if (!activeSheetId && sheets.length > 0) {
                setActiveSheet(sheets[0].id);
            } else if (activeSheetId) {
                // Refresh the active sheet
                renderSpreadsheet();
            }
        } else {
            alert(response.data);
        }
    });
}

function setActiveSheet(sheetId) {
    activeSheetId = sheetId;
    const tabs = document.querySelectorAll('.sheet-tab');
    tabs.forEach(tab => {
        if (parseInt(tab.dataset.sheetId) === sheetId) {
            tab.classList.add('active-tab');
        } else {
            tab.classList.remove('active-tab');
        }
    });
    renderSpreadsheet();
}

function createSheet(spreadsheetId, sheetName) {
    return api('create_sheet', { spreadsheet_id: spreadsheetId, sheet_name: sheetName }).then(response => {
        if (response.status === 'success') {
            alert('Sheet created!');
            listSheets(spreadsheetId);
        } else {
            alert(response.data);
        }
    });
}

function deleteSpreadsheet(spreadsheetId) {
    api('delete_spreadsheet', { spreadsheet_id: spreadsheetId }).then(response => {
        if (response.status === 'success') {
            alert('Spreadsheet deleted!');
            listSpreadsheets();
            document.getElementById('spreadsheet-container').innerHTML = '';
            document.getElementById('tabs-container').innerHTML = '';
        } else {
            alert(response.data);
        }
    });
}

function renameSpreadsheet(spreadsheetId, newName) {
    api('rename_spreadsheet', { spreadsheet_id: spreadsheetId, new_name: newName }).then(response => {
        if (response.status === 'success') {
            alert('Spreadsheet renamed!');
            listSpreadsheets();
        } else {
            alert(response.data);
        }
    });
}

function renameSheet(sheetId, newName) {
    api('rename_sheet', { sheet_id: sheetId, new_name: newName }).then(response => {
        if (response.status === 'success') {
            alert('Sheet renamed!');
            listSheets(activeSpreadsheetId);
        } else {
            alert(response.data);
        }
    });
}

function deleteSheet(sheetId) {
    api('delete_sheet', { sheet_id: sheetId }).then(response => {
        if (response.status === 'success') {
            alert('Sheet deleted!');
            listSheets(activeSpreadsheetId);
        } else {
            alert(response.data);
        }
    });
}

function addSheet() {
    const sheetName = prompt('Enter new sheet name:');
    if (sheetName && sheetName.trim()) {
        createSheet(activeSpreadsheetId, sheetName.trim());
    } else {
        alert('Sheet name cannot be empty.');
    }
}

function addRow() {
    if (!activeSpreadsheetId || !activeSheetId) {
        alert('No active spreadsheet or sheet.');
        return;
    }
    // Determine the next row number based on existing rows
    const table = document.querySelector('#spreadsheet-container table');
    const nextRow = table.rows.length; // since header is row 0
    renderRow(nextRow);
}

function renderRow(rowNumber) {
    const table = document.querySelector('#spreadsheet-container table');
    const rowElem = document.createElement('tr');

    // Row header
    const rowHeader = document.createElement('th');
    rowHeader.textContent = rowNumber;
    rowElem.appendChild(rowHeader);

    for (let c = 0; c < 26; c++) { // 26 columns (A-Z)
        const cellId = `${String.fromCharCode(65 + c)}${rowNumber}`;
        const cellElem = document.createElement('td');
        const input = document.createElement('input');
        input.type = 'text';

        input.dataset.rawValue = '';
        input.dataset.row = rowNumber;
        input.dataset.col = c;
        input.dataset.cell = cellId; // Add data-cell attribute

        // Attach event handlers
        attachInputEvents(input, activeSheetId, rowNumber, c);

        cellElem.appendChild(input);
        rowElem.appendChild(cellElem);
    }
    table.appendChild(rowElem);
}

function fetchSpreadsheetData() {
    if (!activeSpreadsheetId || !activeSheetId) return;
    api('fetch_spreadsheet', { spreadsheet_id: activeSpreadsheetId, sheet_id: activeSheetId }).then(response => {
        if (response.status === 'success') {
            const container = document.getElementById('spreadsheet-container');
            container.innerHTML = '';

            const table = document.createElement('table');

            // Header row
            const headerRow = document.createElement('tr');
            const emptyHeaderCell = document.createElement('th');
            headerRow.appendChild(emptyHeaderCell); // top-left empty cell

            for (let c = 0; c < 26; c++) {
                const headerCell = document.createElement('th');
                headerCell.textContent = String.fromCharCode(65 + c);
                headerCell.setAttribute('col-header', c);
                headerRow.appendChild(headerCell);
            }
            table.appendChild(headerRow);

            // Group DB cells by row/col
            const dbCells = response.data; // each cell = { row, col, value }
            const rows = {};
            dbCells.forEach(cell => {
                if (!rows[cell.row]) rows[cell.row] = {};
                rows[cell.row][cell.col] = cell.value;
            });

            // Decide how many rows to show. (Default 10 or based on data)
            const totalRows = Math.max(...Object.keys(rows).map(Number), 10);

            for (let r = 1; r <= totalRows; r++) {
                const rowElem = document.createElement('tr');
                // Row header
                const rowHeader = document.createElement('th');
                rowHeader.textContent = r;
                rowElem.appendChild(rowHeader);

                for (let c = 0; c < 26; c++) {
                    const cellId = `${String.fromCharCode(65 + c)}${r}`;
                    const cellElem = document.createElement('td');
                    const input = document.createElement('input');
                    input.type = 'text';

                    const rawValue = rows[r]?.[c] || '';
                    input.dataset.rawValue = rawValue;
                    input.dataset.row = r;
                    input.dataset.col = c;
                    input.dataset.cell = cellId; // Add data-cell attribute

                    // Display either formula result or raw
                    input.value = computeCellValue(rawValue);

                    // Attach event handlers
                    attachInputEvents(input, activeSheetId, r, c);

                    cellElem.appendChild(input);
                    rowElem.appendChild(cellElem);
                }
                table.appendChild(rowElem);
            }

            container.appendChild(table);
        } else {
            alert(response.data);
        }
    });
}

function renderSpreadsheet() {
    fetchSpreadsheetData();
}

// -------------------------------------------------------------------
// 6. Authentication and UI Management
// -------------------------------------------------------------------
function login(username, password) {
    if (!username.trim() || !password.trim()) {
        alert('Username and password cannot be empty.');
        return;
    }
    api('login', { username, password }).then(response => {
        if (response.status === 'success') {
            alert('Logged in successfully!');
            toggleVisibility(true);
        } else {
            alert(response.data);
        }
    });
}

function register(username, password) {
    if (!username.trim() || !password.trim()) {
        alert('Username and password cannot be empty.');
        return;
    }
    api('register', { username, password }).then(response => {
        if (response.status === 'success') {
            alert('Registration successful!');
        } else {
            alert(response.data);
        }
    });
}

function logout() {
    api('logout', {}).then(response => {
        if (response.status === 'success') {
            alert('Logged out successfully!');
            toggleVisibility(false);
        } else {
            alert(response.data);
        }
    });
}

function checkSession() {
    api('check_session', {}).then(response => {
        toggleVisibility(response.status === 'success');
    });
}

function toggleVisibility(isLoggedIn) {
    const appSection = document.getElementById('aplicacion');
    const loginSignupSection = document.getElementById('loginsignup');

    if (isLoggedIn) {
        appSection.style.display = 'flex';
        loginSignupSection.style.display = 'none';
        listSpreadsheets(); 
    } else {
        appSection.style.display = 'none';
        loginSignupSection.style.display = 'flex';
    }
}

// -------------------------------------------------------------------
// 7. On Page Load
// -------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    checkSession();
    setupFormulaBarListener();
});
</script>

</body>
</html>


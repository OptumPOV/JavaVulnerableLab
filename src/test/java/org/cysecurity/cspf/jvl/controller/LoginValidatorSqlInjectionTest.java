package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Tests to verify that LoginValidator uses parameterized PreparedStatement
 * queries to prevent SQL Injection (CWE-89) and Second-Order SQL Injection.
 *
 * The second-order injection chain that is tested here:
 *   1. An attacker logs in with a crafted username/password that injects SQL into
 *      the login query (first-order injection — now blocked in LoginValidator).
 *   2. The malicious value gets stored in the session as "userid".
 *   3. That session value is later used in change-info.jsp's UPDATE query
 *      (second-order sink — now also blocked by using PreparedStatement).
 *
 * Because the fix is applied to production Java/JSP source code we verify it
 * through static source analysis (reading the source as a String) rather than
 * running a live database.  This approach is commonly used for JSP/Servlet
 * projects where spinning up a real DB in unit tests is not practical.
 */
public class LoginValidatorSqlInjectionTest extends TestCase {

    // ---------- helpers -------------------------------------------------------

    /**
     * Reads the source of a file on the classpath-relative path given.
     * The paths are rooted at the Maven source tree so CI can find them.
     */
    private String readSource(String relativePath) throws Exception {
        java.io.InputStream is = getClass().getClassLoader()
                .getResourceAsStream(relativePath);
        if (is == null) {
            // Fall back to file-system path (works when tests are run from the
            // project root, which is the normal Maven layout).
            java.io.File f = new java.io.File(relativePath);
            if (!f.exists()) {
                // Try from project root as supplied by surefire
                String basedir = System.getProperty("basedir", ".");
                f = new java.io.File(basedir + "/" + relativePath);
            }
            if (!f.exists()) {
                return null; // Let the test handle a missing file gracefully
            }
            is = new java.io.FileInputStream(f);
        }
        try (java.io.BufferedReader reader =
                     new java.io.BufferedReader(new java.io.InputStreamReader(is))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            return sb.toString();
        }
    }

    // ---------- LoginValidator tests ------------------------------------------

    /**
     * Verify that LoginValidator.java imports PreparedStatement (not just Statement).
     * The import signals that the parameterized-query pattern is in use.
     */
    public void testLoginValidatorImportsPreparedStatement() throws Exception {
        String src = readSource(
                "src/main/java/org/cysecurity/cspf/jvl/controller/LoginValidator.java");
        assertNotNull("LoginValidator.java source must be readable", src);
        assertTrue(
                "LoginValidator must import java.sql.PreparedStatement to use parameterized queries",
                src.contains("import java.sql.PreparedStatement"));
    }

    /**
     * Verify that the login SELECT in LoginValidator.java uses a PreparedStatement
     * (con.prepareStatement) rather than raw Statement concatenation.
     */
    public void testLoginQueryUsesParameterizedQuery() throws Exception {
        String src = readSource(
                "src/main/java/org/cysecurity/cspf/jvl/controller/LoginValidator.java");
        assertNotNull("LoginValidator.java source must be readable", src);

        // Must NOT contain the old string-concatenation login query pattern
        assertFalse(
                "Login SELECT query must NOT concatenate user-controlled username directly into SQL string",
                src.contains("\"select * from users where username='\"+user+\"'"));

        // Must use prepareStatement for the login query
        assertTrue(
                "Login SELECT query must use con.prepareStatement() for parameterized execution",
                src.contains("con.prepareStatement(") || src.contains("conn.prepareStatement("));
    }

    /**
     * Verify that the parameterized login query includes '?' placeholders for
     * both username and password.
     */
    public void testLoginQueryHasParameterPlaceholders() throws Exception {
        String src = readSource(
                "src/main/java/org/cysecurity/cspf/jvl/controller/LoginValidator.java");
        assertNotNull("LoginValidator.java source must be readable", src);

        // The query string must use ? for both username and password
        assertTrue(
                "Parameterized login query must contain '?' placeholder for username",
                src.contains("username=?"));
        assertTrue(
                "Parameterized login query must contain '?' placeholder for password",
                src.contains("password=?"));
    }

    /**
     * Verify that setString() is called to bind username and password parameters
     * so that user-controlled data is never interpreted as SQL.
     */
    public void testLoginQueryBindsParametersWithSetString() throws Exception {
        String src = readSource(
                "src/main/java/org/cysecurity/cspf/jvl/controller/LoginValidator.java");
        assertNotNull("LoginValidator.java source must be readable", src);

        assertTrue(
                "PreparedStatement must call setString(1, user) to bind the username parameter",
                src.contains("setString(1, user)"));
        assertTrue(
                "PreparedStatement must call setString(2, pass) to bind the password parameter",
                src.contains("setString(2, pass)"));
    }

    // ---------- change-info.jsp tests -----------------------------------------

    /**
     * Verify that change-info.jsp imports PreparedStatement to use parameterized queries.
     */
    public void testChangeInfoImportsPreparedStatement() throws Exception {
        String src = readSource(
                "src/main/webapp/vulnerability/csrf/change-info.jsp");
        assertNotNull("change-info.jsp source must be readable", src);

        assertTrue(
                "change-info.jsp must import java.sql.PreparedStatement",
                src.contains("import java.sql.PreparedStatement"));
    }

    /**
     * Verify that the UPDATE query in change-info.jsp is NOT built by string
     * concatenation with the session-sourced 'id' value.
     * This is the sink of the second-order SQL injection.
     */
    public void testChangeInfoUpdateDoesNotConcatenateId() throws Exception {
        String src = readSource(
                "src/main/webapp/vulnerability/csrf/change-info.jsp");
        assertNotNull("change-info.jsp source must be readable", src);

        // Old vulnerable patterns that concatenate 'id' directly into the SQL
        assertFalse(
                "UPDATE query must NOT concatenate 'id' into SQL string (second-order injection sink)",
                src.contains("where id=\"+id") || src.contains("where id=\" + id") ||
                src.contains("where id=\" +id") || src.contains("where id=\"+ id"));

        // Also check for the about column concatenation with 'info'
        assertFalse(
                "UPDATE query must NOT concatenate 'info' into SQL string",
                src.contains("about='\"+info+\"'") || src.contains("about='\" + info + \"'"));
    }

    /**
     * Verify that change-info.jsp uses prepareStatement() for the UPDATE.
     */
    public void testChangeInfoUpdateUsesParameterizedQuery() throws Exception {
        String src = readSource(
                "src/main/webapp/vulnerability/csrf/change-info.jsp");
        assertNotNull("change-info.jsp source must be readable", src);

        assertTrue(
                "change-info.jsp UPDATE must use con.prepareStatement() to prevent second-order SQL injection",
                src.contains("con.prepareStatement(") || src.contains("conn.prepareStatement("));
    }

    /**
     * Verify that the parameterized UPDATE query in change-info.jsp has '?' for
     * both the 'about' column and the 'id' predicate.
     */
    public void testChangeInfoUpdateHasParameterPlaceholders() throws Exception {
        String src = readSource(
                "src/main/webapp/vulnerability/csrf/change-info.jsp");
        assertNotNull("change-info.jsp source must be readable", src);

        // Expect "about=?" in the UPDATE statement
        assertTrue(
                "Parameterized UPDATE must use '?' for the about column value",
                src.contains("about=?"));
        // Expect "id=?" in the WHERE clause
        assertTrue(
                "Parameterized UPDATE must use '?' for the id column in WHERE clause",
                src.contains("id=?"));
    }

    /**
     * Verify that setString() is called to bind parameters in change-info.jsp,
     * ensuring the session-sourced 'id' is treated as data, not as SQL code.
     */
    public void testChangeInfoUpdateBindsParametersWithSetString() throws Exception {
        String src = readSource(
                "src/main/webapp/vulnerability/csrf/change-info.jsp");
        assertNotNull("change-info.jsp source must be readable", src);

        assertTrue(
                "PreparedStatement must bind 'info' with setString to prevent injection of the about field",
                src.contains("setString(1, info)"));
        assertTrue(
                "PreparedStatement must bind 'id' with setString to prevent second-order injection via session id",
                src.contains("setString(2, id)"));
    }

    /**
     * Verify that the PreparedStatement is explicitly closed after use in change-info.jsp
     * to prevent resource leaks.
     */
    public void testChangeInfoClosesStatement() throws Exception {
        String src = readSource(
                "src/main/webapp/vulnerability/csrf/change-info.jsp");
        assertNotNull("change-info.jsp source must be readable", src);

        assertTrue(
                "PreparedStatement must be closed after use to prevent resource leaks",
                src.contains("pstmt.close()") || src.contains(".close()"));
    }

    // ---------- Second-Order injection chain regression tests -----------------

    /**
     * Confirm that neither file contains the original vulnerable string-concatenation
     * SQL pattern that formed the full second-order injection chain.
     *
     * The chain was:
     *   1. LoginValidator: "select * from users where username='" + user + "'"
     *      → attacker stores malicious id in DB
     *   2. change-info.jsp: "Update users set about='" + info + "' where id=" + id
     *      → stored malicious id executes as SQL
     *
     * Both legs must be absent from the fixed code.
     */
    public void testSecondOrderInjectionChainIsFullyBroken() throws Exception {
        String loginSrc = readSource(
                "src/main/java/org/cysecurity/cspf/jvl/controller/LoginValidator.java");
        String changeInfoSrc = readSource(
                "src/main/webapp/vulnerability/csrf/change-info.jsp");

        assertNotNull("LoginValidator.java source must be readable", loginSrc);
        assertNotNull("change-info.jsp source must be readable", changeInfoSrc);

        // Leg 1: login query must not concatenate user input
        assertFalse(
                "Second-order chain leg 1 (LoginValidator login query) must not use string concatenation",
                loginSrc.contains("username='\"+user+\"'") ||
                loginSrc.contains("username='\" + user + \"'"));

        // Leg 2: update query must not concatenate id from session
        assertFalse(
                "Second-order chain leg 2 (change-info.jsp UPDATE query) must not concatenate session id",
                changeInfoSrc.contains("where id=\"+id") ||
                changeInfoSrc.contains("where id=\" + id") ||
                changeInfoSrc.contains("where id=\" +id") ||
                changeInfoSrc.contains("where id=\" + id"));
    }
}

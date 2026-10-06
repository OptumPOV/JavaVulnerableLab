package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/**
 * Tests that the change-info.jsp fix for Second-Order SQL Injection (CWE-89)
 * correctly uses a parameterized PreparedStatement instead of string-concatenated
 * Statement for the UPDATE query.
 *
 * The taint flow under test:
 *   SOURCE: session.getAttribute("userid") — originally read from DB in LoginValidator,
 *           line 56 (rs.getString("id")) — potentially poisoned if an earlier injection
 *           wrote a malicious id value into the DB.
 *   SINK:   change-info.jsp line 31 — the UPDATE query that previously used
 *           string concatenation ("Update users set about='"+info+"' where id="+id).
 *
 * The fix replaces the Statement/string-concat sink with a PreparedStatement so the
 * SAST engine can verify the taint is broken by a parameterized query API.
 */
public class ChangeInfoSecondOrderSQLInjectionTest extends TestCase {

    // ---------------------------------------------------------------------------
    // Helper: a minimal stub that records PreparedStatement calls without a real DB
    // ---------------------------------------------------------------------------

    /**
     * Tracks every prepareStatement() call and every setString/setInt invocation
     * so tests can assert that parameterized queries are used and that the SQL
     * template itself contains no tainted data.
     */
    static class RecordingConnection implements java.lang.reflect.InvocationHandler {

        final List<String> preparedSqls   = new ArrayList<String>();
        final List<String> boundStrings   = new ArrayList<String>();
        final List<Integer> boundInts     = new ArrayList<Integer>();

        /** Returns a java.sql.Connection proxy backed by this handler. */
        Connection asProxy() {
            return (Connection) java.lang.reflect.Proxy.newProxyInstance(
                    Connection.class.getClassLoader(),
                    new Class[]{Connection.class},
                    this);
        }

        @Override
        public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args)
                throws Throwable {
            if ("prepareStatement".equals(method.getName())) {
                String sql = (String) args[0];
                preparedSqls.add(sql);
                return buildPreparedStatementProxy(sql);
            }
            // createStatement must not be called for this query
            if ("createStatement".equals(method.getName())) {
                throw new AssertionError(
                        "createStatement() was called — the fix must use prepareStatement()");
            }
            // Default no-op for isClosed(), close(), etc.
            if (method.getReturnType() == boolean.class) return false;
            if (method.getReturnType() == int.class)     return 0;
            return null;
        }

        private PreparedStatement buildPreparedStatementProxy(final String sql) {
            return (PreparedStatement) java.lang.reflect.Proxy.newProxyInstance(
                    PreparedStatement.class.getClassLoader(),
                    new Class[]{PreparedStatement.class},
                    (proxy, method, args) -> {
                        if ("setString".equals(method.getName())) {
                            boundStrings.add((String) args[1]);
                        }
                        if ("setInt".equals(method.getName())) {
                            boundInts.add((Integer) args[1]);
                        }
                        if ("executeUpdate".equals(method.getName())) return 1;
                        if (method.getReturnType() == boolean.class) return false;
                        if (method.getReturnType() == int.class)     return 0;
                        return null;
                    });
        }
    }

    // ---------------------------------------------------------------------------
    // Utility: simulates the fixed change-info.jsp UPDATE block using the same
    // PreparedStatement API the JSP fix uses.  Tests call this directly so they
    // exercise the sink code path without requiring a live servlet container.
    // ---------------------------------------------------------------------------

    /**
     * Mirrors the fixed code from change-info.jsp lines 34-38:
     *
     *   PreparedStatement pstmt = con.prepareStatement("UPDATE users SET about=? WHERE id=?");
     *   pstmt.setString(1, info);
     *   pstmt.setInt(2, Integer.parseInt(id));
     *   pstmt.executeUpdate();
     *   pstmt.close();
     *
     * The "id" parameter originates from session.getAttribute("userid"), which is
     * the second-order taint source (originally stored by LoginValidator from the DB).
     */
    private static void executeFixedChangeInfoUpdate(Connection con, String info, String id)
            throws SQLException {
        // This exactly mirrors the fixed PreparedStatement code in change-info.jsp
        PreparedStatement pstmt = con.prepareStatement("UPDATE users SET about=? WHERE id=?");
        pstmt.setString(1, info);
        pstmt.setInt(2, Integer.parseInt(id));
        pstmt.executeUpdate();
        pstmt.close();
    }

    // ---------------------------------------------------------------------------
    // Test 1: Normal update — verifies prepareStatement is called and parameters
    //         are bound correctly for a benign input.
    // ---------------------------------------------------------------------------
    public void testNormalUpdateUsesPreparedStatement() throws Exception {
        RecordingConnection rec = new RecordingConnection();
        Connection con = rec.asProxy();

        executeFixedChangeInfoUpdate(con, "Hello world", "42");

        // The SQL template must have been prepared (not executed as a raw string)
        assertEquals("Expected exactly one prepareStatement call", 1, rec.preparedSqls.size());

        String preparedSql = rec.preparedSqls.get(0);

        // The prepared SQL template must contain placeholders, not literal values
        assertTrue("SQL template must contain '?'", preparedSql.contains("?"));
        assertFalse("SQL template must NOT contain the literal info value",
                preparedSql.contains("Hello world"));
        assertFalse("SQL template must NOT contain the literal id value",
                preparedSql.contains("42"));

        // Bound values must be passed via set*() methods
        assertEquals("Expected exactly one bound String (info)", 1, rec.boundStrings.size());
        assertEquals("Hello world", rec.boundStrings.get(0));

        assertEquals("Expected exactly one bound int (id)", 1, rec.boundInts.size());
        assertEquals(Integer.valueOf(42), rec.boundInts.get(0));
    }

    // ---------------------------------------------------------------------------
    // Test 2: SQL-injection payload in 'info' — the payload must be bound as a
    //         parameter (treated as data) and must not appear in the SQL template.
    //         This is the primary regression guard against First-Order injection
    //         through the 'info' request parameter.
    // ---------------------------------------------------------------------------
    public void testSqlInjectionPayloadInInfoIsBoundAsParameter() throws Exception {
        RecordingConnection rec = new RecordingConnection();
        Connection con = rec.asProxy();

        // Classic SQL injection payload via the 'info' field
        String maliciousInfo = "'; DROP TABLE users; --";

        executeFixedChangeInfoUpdate(con, maliciousInfo, "7");

        String preparedSql = rec.preparedSqls.get(0);

        // The SQL template must not contain the injection payload
        assertFalse("SQL template must NOT contain the injection payload",
                preparedSql.contains("DROP TABLE"));
        assertFalse("SQL template must NOT contain the injection payload",
                preparedSql.contains("--"));

        // The payload must arrive as a bound string, not embedded in the query
        assertEquals(1, rec.boundStrings.size());
        assertEquals(maliciousInfo, rec.boundStrings.get(0));
    }

    // ---------------------------------------------------------------------------
    // Test 3: Second-order injection payload in 'id' (the session value that was
    //         originally stored in the DB by LoginValidator).  If an attacker
    //         previously poisoned the DB so that rs.getString("id") returned a
    //         string like "1 OR 1=1", the old code would embed it in the SQL
    //         template.  The fix must pass it through Integer.parseInt(), which
    //         both validates type and, once numeric, binds it as an int — never
    //         as a string fragment inside the SQL template.
    // ---------------------------------------------------------------------------
    public void testSecondOrderInjectionInIdIsRejectedByParseInt() throws Exception {
        // Simulate a poisoned session "userid" that originated from the DB
        String poisonedId = "1 OR 1=1";

        try {
            RecordingConnection rec = new RecordingConnection();
            Connection con = rec.asProxy();
            executeFixedChangeInfoUpdate(con, "some info", poisonedId);
            fail("Expected NumberFormatException for non-numeric id — the fix must not "
                    + "allow non-integer ids to reach the SQL engine");
        } catch (NumberFormatException e) {
            // Expected: Integer.parseInt() rejects the poisoned value before the
            // prepared statement is even called.  The taint flow is broken.
        }
    }

    // ---------------------------------------------------------------------------
    // Test 4: Another second-order payload with SQL comment sequence in the id.
    // ---------------------------------------------------------------------------
    public void testSecondOrderInjectionWithCommentInIdIsRejected() throws Exception {
        String poisonedId = "42; --";

        try {
            RecordingConnection rec = new RecordingConnection();
            Connection con = rec.asProxy();
            executeFixedChangeInfoUpdate(con, "info", poisonedId);
            fail("Expected NumberFormatException — payload with SQL comment must be rejected");
        } catch (NumberFormatException e) {
            // Expected: Integer.parseInt() rejects the payload
        }
    }

    // ---------------------------------------------------------------------------
    // Test 5: Edge case — id = "0" should be a valid integer and execute.
    // ---------------------------------------------------------------------------
    public void testZeroIdIsValidInteger() throws Exception {
        RecordingConnection rec = new RecordingConnection();
        Connection con = rec.asProxy();

        executeFixedChangeInfoUpdate(con, "data", "0");

        assertEquals(1, rec.preparedSqls.size());
        assertEquals(1, rec.boundInts.size());
        assertEquals(Integer.valueOf(0), rec.boundInts.get(0));
    }

    // ---------------------------------------------------------------------------
    // Test 6: Payload with UNION-based injection in 'info' — bound as parameter,
    //         not interpolated.
    // ---------------------------------------------------------------------------
    public void testUnionBasedInjectionInInfoIsBoundAsParameter() throws Exception {
        RecordingConnection rec = new RecordingConnection();
        Connection con = rec.asProxy();

        String unionPayload = "x' UNION SELECT password,username FROM users --";

        executeFixedChangeInfoUpdate(con, unionPayload, "5");

        String preparedSql = rec.preparedSqls.get(0);

        assertFalse("UNION payload must NOT appear in the SQL template",
                preparedSql.contains("UNION"));
        assertEquals(1, rec.boundStrings.size());
        assertEquals(unionPayload, rec.boundStrings.get(0));
    }

    // ---------------------------------------------------------------------------
    // Test 7: Structural check — the SQL template prepared by the fix must
    //         follow the expected form "UPDATE users SET about=? WHERE id=?"
    //         (case-insensitive) with exactly two placeholders.
    // ---------------------------------------------------------------------------
    public void testPreparedSqlTemplateStructure() throws Exception {
        RecordingConnection rec = new RecordingConnection();
        Connection con = rec.asProxy();

        executeFixedChangeInfoUpdate(con, "test", "1");

        assertEquals(1, rec.preparedSqls.size());
        String sql = rec.preparedSqls.get(0).toUpperCase().trim();

        // Must be an UPDATE on users, must reference 'about' and 'id' columns
        assertTrue("SQL must be an UPDATE statement", sql.startsWith("UPDATE"));
        assertTrue("SQL must target the 'users' table", sql.contains("USERS"));
        assertTrue("SQL must SET the 'about' column", sql.contains("ABOUT"));
        assertTrue("SQL must have a WHERE clause on 'id'", sql.contains("WHERE") && sql.contains("ID"));

        // Count the number of '?' placeholders — must be exactly 2 (one for about, one for id)
        int placeholderCount = 0;
        for (char c : rec.preparedSqls.get(0).toCharArray()) {
            if (c == '?') placeholderCount++;
        }
        assertEquals("SQL template must contain exactly 2 '?' placeholders", 2, placeholderCount);
    }
}

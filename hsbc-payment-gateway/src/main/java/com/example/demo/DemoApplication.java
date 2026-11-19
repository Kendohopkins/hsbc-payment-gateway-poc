// package com.example.demo;

// import org.springframework.boot.SpringApplication;
// import org.springframework.boot.autoconfigure.SpringBootApplication;

// @SpringBootApplication
// public class DemoApplication {
 // public static void main(String[] args) {
  //  SpringApplication.run(DemoApplication.class, args);
 // }
// }

package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/*
 * ⚠️ TRAINING CODE — INTENTIONALLY VULNERABLE. DO NOT DEPLOY.
 * Used to demonstrate SonarQube bugs, vulnerabilities, security hotspots and code smells.
 *
 * FIXED: VULN 2 (SQL injection), VULN 3 (command injection), VULN 4 (path traversal).
 * The remaining issues are left in place.
 */
@SpringBootApplication
public class DemoApplication {

	// VULN 1: Hard-coded credentials (S2068 / S6437)
	private static final String DB_URL = "jdbc:mysql://localhost:3306/shop";
	private static final String DB_USER = "admin";
	private static final String DB_PASSWORD = "SuperSecret123!";

	// CODE SMELL: Unused private field (S1068)
	private String unusedConfig = "not used anywhere";

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	@RestController
	static class VulnerableController {

		// Allow-list for hostnames / IPv4 addresses: letters, digits, dots and hyphens,
		// and it cannot start with "-", so the value can never be read as a ping option.
		private static final Pattern HOST_PATTERN =
				Pattern.compile("^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$");

		// FIXED (was VULN 2): parameterized query + try-with-resources.
		@GetMapping("/user")
		public String getUser(@RequestParam String name) throws Exception {
			String sql = "SELECT email FROM users WHERE name = ?";
			try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
			     PreparedStatement ps = conn.prepareStatement(sql)) {
				ps.setString(1, name);
				try (ResultSet rs = ps.executeQuery()) {
					return rs.next() ? rs.getString("email") : "not found";
				}
			}
		}

		// FIXED (was VULN 3): the host is validated against an allow-list and passed to
		// ProcessBuilder as a separate argument, so no shell is involved and characters
		// like ";", "|" or "&&" cannot start another command. Reader is now closed too.
		@GetMapping("/ping")
		public String ping(@RequestParam String host) throws Exception {
			if (!HOST_PATTERN.matcher(host).matches()) {
				throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid host");
			}
			Process p = new ProcessBuilder("ping", "-c", "1", "-W", "2", host)
					.redirectErrorStream(true)
					.start();
			try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
				String line = reader.readLine();
				if (!p.waitFor(5, TimeUnit.SECONDS)) {
					p.destroyForcibly();
				}
				return line;
			} finally {
				p.destroy();
			}
		}

		// FIXED (was VULN 4): the requested path is resolved against the base directory,
		// normalized, and rejected unless the real path (symlinks resolved) is still
		// inside that directory. Absolute paths and "../" sequences are therefore refused.
		@GetMapping("/read")
		public String readFile(@RequestParam String file) throws Exception {
			Path baseDir = Paths.get("/app/files").toRealPath();
			Path target = baseDir.resolve(file).normalize();
			if (!target.startsWith(baseDir)) {
				throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid file path");
			}
			if (!Files.isRegularFile(target)) {
				throw new ResponseStatusException(HttpStatus.NOT_FOUND, "File not found");
			}
			if (!target.toRealPath().startsWith(baseDir)) {
				throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid file path");
			}
			try (BufferedReader br = Files.newBufferedReader(target)) {
				String line = br.readLine();
				return line != null ? line : "";
			}
		}

		// VULN 5: Weak hashing algorithm, MD5 (S4790)
		@GetMapping("/hash")
		public String hash(@RequestParam String password) throws Exception {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] digest = md.digest(password.getBytes());
			StringBuilder sb = new StringBuilder();
			for (byte b : digest) sb.append(String.format("%02x", b));
			return sb.toString();
		}

		// VULN 6: Insecure pseudorandom generator used for a token (S2245)
		@GetMapping("/token")
		public String token() {
			Random random = new Random();
			return "TOKEN-" + random.nextInt(999999);
		}

		// CODE SMELLS: empty catch (S108), System.out logging (S106), printStackTrace (S1148)
		@GetMapping("/divide")
		public int divide(@RequestParam int a, @RequestParam int b) {
			try {
				return a / b;
			} catch (ArithmeticException e) {
				// swallowed
			}
			try {
				System.out.println("Dividing " + a + " by " + b);
			} catch (Exception e) {
				e.printStackTrace();
			}
			return 0;
		}
	}
}
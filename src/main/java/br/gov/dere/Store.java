package br.gov.dere;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.time.*;

public final class Store {
  static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
  static final Path ROOT = Path.of(System.getProperty("user.home"), ".dere-desktop");
  static final Path CONFIG = ROOT.resolve("config.json"), STATE = ROOT.resolve("protocolos.json"),
      OUT = ROOT.resolve("retornos");

  static ObjectNode config() {
    return read(CONFIG);
  }

  static ObjectNode state() {
    return read(STATE);
  }

  static ObjectNode read(Path p) {
    try {
      Files.createDirectories(ROOT);
      return Files.exists(p) ? (ObjectNode) JSON.readTree(p.toFile()) : JSON.createObjectNode();
    } catch (Exception e) {
      return JSON.createObjectNode();
    }
  }

  static void write(Path p, JsonNode n) throws Exception {
    Files.createDirectories(p.getParent());
    try {
      Files.setPosixFilePermissions(ROOT, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
    } catch (UnsupportedOperationException ignored) {
    }
    JSON.writeValue(p.toFile(), n);
    if (p.equals(CONFIG))
      try {
        Files.setPosixFilePermissions(p, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
      } catch (UnsupportedOperationException ignored) {
      }
  }

  static void record(String protocol, String cnpj, String lote) throws Exception {
    ObjectNode s = state(), row = JSON.createObjectNode();
    row.put("protocolo", protocol);
    row.put("cnpj", cnpj);
    row.put("lote", lote);
    row.put("enviadoEm", Instant.now().toString());
    row.put("status", "Recebido");
    s.withArray("lotes").add(row);
    write(STATE, s);
  }
}

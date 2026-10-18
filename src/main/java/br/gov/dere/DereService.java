package br.gov.dere;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.w3c.dom.*;
import javax.xml.XMLConstants;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.validation.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.time.*;
import java.util.*;

final class DereService {
  private static final Map<String, CachedToken> tokenCache = new HashMap<>();

  private record CachedToken(String value, long expiresAt) {
  }

  static Document parse(Path p) throws Exception {
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
    f.setNamespaceAware(true);
    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    f.setFeature("http://xml.org/sax/features/external-general-entities", false);
    f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    return f.newDocumentBuilder().parse(p.toFile());
  }

  static Document parse(String xml) throws Exception {
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
    f.setNamespaceAware(true);
    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    f.setFeature("http://xml.org/sax/features/external-general-entities", false);
    f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    return f.newDocumentBuilder().parse(new org.xml.sax.InputSource(new java.io.StringReader(xml)));
  }

  static byte[] bytes(Document d) throws Exception {
    TransformerFactory tf = TransformerFactory.newInstance();
    tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    Transformer t = tf.newTransformer();
    t.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
    t.setOutputProperty(OutputKeys.INDENT, "yes");
    ByteArrayOutputStream b = new ByteArrayOutputStream();
    t.transform(new DOMSource(d), new StreamResult(b));
    return b.toByteArray();
  }

  static String name(Document d) {
    return d.getDocumentElement().getLocalName();
  }

  static String schemaFor(Document d) {
    String n = name(d);
    if (n.equals("DeRE") && d.getDocumentElement().getNamespaceURI().contains("envioLoteDere"))
      return "envioLoteDere-v1_0_1.xsd";
    return switch (n) {
      case "DeRE" -> d.getDocumentElement().getNamespaceURI().contains("evtPGCC") ? "evtPGCC-v1_0_3.xsd"
          : "evtInfoContrib-v1_0_1.xsd";
      default -> "evtInfoContrib-v1_0_1.xsd";
    };
  }

  static void validate(Path file, String schema) throws Exception {
    SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    sf.setResourceResolver((type, namespace, publicId, systemId, baseURI) -> {
      if (systemId != null && systemId.endsWith("xmldsig-core-schema.xsd")) {
        try (InputStream x = DereService.class.getResourceAsStream("/xsd/xmldsig-core-schema.xsd")) {
          return new SchemaInput(new String(x.readAllBytes(), StandardCharsets.UTF_8), systemId, publicId, baseURI);
        } catch (Exception ex) {
          throw new IllegalStateException(ex);
        }
      }
      return null;
    });
    try (InputStream in = DereService.class.getResourceAsStream("/xsd/" + schema)) {
      if (in == null)
        throw new FileNotFoundException(schema);
      Validator validator = sf.newSchema(new javax.xml.transform.stream.StreamSource(in)).newValidator();
      validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
      validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
      validator.validate(new javax.xml.transform.stream.StreamSource(file.toFile()));
    }
  }

  private static final class SchemaInput implements org.w3c.dom.ls.LSInput {
    private java.io.Reader chars;
    private String systemId, publicId, baseURI, encoding;
    private boolean certified;

    SchemaInput(String text, String systemId, String publicId, String baseURI) {
      this.chars = new java.io.StringReader(text);
      this.systemId = systemId;
      this.publicId = publicId;
      this.baseURI = baseURI;
    }

    public java.io.Reader getCharacterStream() {
      return chars;
    }

    public void setCharacterStream(java.io.Reader x) {
      chars = x;
    }

    public java.io.InputStream getByteStream() {
      return null;
    }

    public void setByteStream(java.io.InputStream x) {
    }

    public String getStringData() {
      return null;
    }

    public void setStringData(String x) {
      chars = new java.io.StringReader(x);
    }

    public String getSystemId() {
      return systemId;
    }

    public void setSystemId(String x) {
      systemId = x;
    }

    public String getPublicId() {
      return publicId;
    }

    public void setPublicId(String x) {
      publicId = x;
    }

    public String getBaseURI() {
      return baseURI;
    }

    public void setBaseURI(String x) {
      baseURI = x;
    }

    public String getEncoding() {
      return encoding;
    }

    public void setEncoding(String x) {
      encoding = x;
    }

    public boolean getCertifiedText() {
      return certified;
    }

    public void setCertifiedText(boolean x) {
      certified = x;
    }
  }

  static String validateEvent(Path p) throws Exception {
    Document d = parse(p);
    String s = schemaFor(d);
    validate(p, s);
    return s;
  }

  static void sign(Path p, Path certFile, char[] password) throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(certFile)) {
      ks.load(in, password);
    }
    String alias = ks.aliases().nextElement();
    PrivateKey key = (PrivateKey) ks.getKey(alias, password);
    X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
    Document d = parse(p);
    // Re-signing must replace the previous enveloped signature instead of adding
    // a second ds:Signature, which the DeRE event XSD rejects.
    NodeList oldSignatures = d.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    for (int i = oldSignatures.getLength() - 1; i >= 0; i--) {
      Node old = oldSignatures.item(i);
      old.getParentNode().removeChild(old);
    }
    Element target = null;
    NodeList all = d.getElementsByTagName("*");
    for (int i = 0; i < all.getLength(); i++) {
      Element e = (Element) all.item(i);
      if (e.hasAttribute("id") || e.hasAttribute("Id")) {
        String a = e.hasAttribute("id") ? "id" : "Id";
        e.setIdAttribute(a, true);
        target = e;
        break;
      }
    }
    if (target == null)
      throw new IllegalArgumentException("Não encontrei o atributo id/Id do evento para referenciar na assinatura.");
    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
    Reference ref = fac.newReference(
        "#" + (target.hasAttribute("id") ? target.getAttribute("id") : target.getAttribute("Id")),
        fac.newDigestMethod(DigestMethod.SHA256, null),
        List.of(fac.newTransform(Transform.ENVELOPED, (javax.xml.crypto.dsig.spec.TransformParameterSpec) null), fac
            .newTransform(CanonicalizationMethod.INCLUSIVE, (javax.xml.crypto.dsig.spec.TransformParameterSpec) null)),
        null, null);
    SignedInfo si = fac.newSignedInfo(
        fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
        fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null), List.of(ref));
    KeyInfoFactory kif = fac.getKeyInfoFactory();
    X509Data xd = kif.newX509Data(List.of(cert));
    KeyInfo ki = kif.newKeyInfo(List.of(xd));
    fac.newXMLSignature(si, ki).sign(new DOMSignContext(key, d.getDocumentElement()));
    Files.write(p, bytes(d));
  }

  static synchronized String token(ObjectNode c) throws Exception {
    String environment = c.path("ambiente").asText("Produção Restrita");
    ObjectNode profile = profile(c, environment);
    String id = profile.path("clientId").asText(c.path("clientId").asText());
    String secret = profile.path("clientSecret").asText(c.path("clientSecret").asText());
    if (id.isBlank() || secret.isBlank())
      throw new IllegalStateException("Configure client ID e client secret para " + environment + " em Parâmetros.");
    String tokenUrl = tokenEndpoint(environment);
    String fingerprint = Base64.getEncoder().encodeToString(
        MessageDigest.getInstance("SHA-256").digest((tokenUrl + ":" + id + ":" + secret).getBytes(StandardCharsets.UTF_8)));
    long now = System.currentTimeMillis();
    CachedToken cached = tokenCache.get(fingerprint);
    if (cached != null && now < cached.expiresAt() - 60_000)
      return cached.value();
    String basic = Base64.getEncoder().encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
    HttpRequest req = HttpRequest.newBuilder(URI.create(tokenUrl))
        .header("Authorization", "Basic " + basic).header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials")).build();
    HttpResponse<String> res = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
    if (res.statusCode() / 100 != 2)
      throw new IOException("OAuth HTTP " + res.statusCode() + ": " + res.body());
    JsonNode body = Store.JSON.readTree(res.body());
    String accessToken = body.path("access_token").asText();
    if (accessToken.isBlank())
      throw new IOException("Resposta OAuth sem access_token: " + res.body());
    long expiresAt = now + Math.max(60, body.path("expires_in").asLong(3600)) * 1000;
    tokenCache.put(fingerprint, new CachedToken(accessToken, expiresAt));
    return accessToken;
  }

  static String submit(Path p) throws Exception {
    ObjectNode c = Store.config();
    String token = token(c), base = base(c);
    HttpRequest req = HttpRequest.newBuilder(URI.create(base + "/v1/recepcao/lotes"))
        .header("Authorization", "Bearer " + token).header("Content-Type", "application/xml")
        .POST(HttpRequest.BodyPublishers.ofFile(p)).build();
    HttpResponse<String> r = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
    if (r.statusCode() / 100 != 2)
      throw new IOException("Envio HTTP " + r.statusCode() + ": " + r.body());
    String body = r.body().trim(), protocol = "";
    if (body.startsWith("<")) {
      Document d = parse(body);
      NodeList n = d.getElementsByTagNameNS("*", "protocolo");
      if (n.getLength() > 0)
        protocol = n.item(0).getTextContent().trim();
    } else {
      JsonNode j = Store.JSON.readTree(body);
      protocol = j.path("protocolo").asText(j.path("protocoloRecebimento").asText(""));
    }
    if (protocol.isBlank())
      throw new IOException("Resposta sem protocolo: " + r.body());
    return protocol;
  }

  static String base(ObjectNode c) {
    String environment = c.path("ambiente").asText("Produção Restrita");
    ObjectNode profile = profile(c, environment);
    String configured = profile.path("apiBase").asText("").trim();
    if (configured.isBlank() && environment.equals("Produção"))
      configured = c.path("apiBase").asText("").trim();
    if (environment.equals("Produção Restrita") && configured.isBlank())
      configured = "https://api.receitafederal.gov.br/prr-dere";
    if (environment.equals("Produção") && (configured.isBlank() || configured.contains("/prr-dere")))
      throw new IllegalStateException(
          "Informe a URL base oficial da API DeRE de Produção nos parâmetros. A documentação fornecida não especifica essa URL.");
    return configured.replaceAll("/+$", "");
  }

  static String tokenEndpoint(String environment) {
    return environment.equals("Produção")
        ? "https://api.receitafederal.gov.br/token"
        : "https://h-api.receitafederal.gov.br/token";
  }

  private static ObjectNode profile(ObjectNode config, String environment) {
    JsonNode profiles = config.path("ambientes");
    if (profiles.isObject() && profiles.path(environment).isObject())
      return (ObjectNode) profiles.path(environment);
    ObjectNode legacy = Store.JSON.createObjectNode();
    if (config.path("ambiente").asText("Produção Restrita").equals(environment)) {
      legacy.put("clientId", config.path("clientId").asText(""));
      legacy.put("clientSecret", config.path("clientSecret").asText(""));
      String oldBase = config.path("apiBase").asText("");
      if (!environment.equals("Produção") || !oldBase.contains("/prr-dere"))
        legacy.put("apiBase", oldBase);
    }
    return legacy;
  }

  static String consult(String protocol) throws Exception {
    ObjectNode c = Store.config();
    HttpRequest req = HttpRequest
        .newBuilder(URI.create(base(c) + "/v1/consulta/lotes/" + URLEncoder.encode(protocol, StandardCharsets.UTF_8)))
        .header("Authorization", "Bearer " + token(c)).GET().build();
    HttpResponse<String> r = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
    if (r.statusCode() / 100 != 2)
      throw new IOException("Consulta HTTP " + r.statusCode() + ": " + r.body());
    return r.body();
  }

  static String baseCnpj(String c) {
    String x = c.replaceAll("[^A-Za-z0-9]", "").toUpperCase(Locale.ROOT);
    if (x.length() != 14)
      throw new IllegalArgumentException("Informe um CNPJ válido com 14 caracteres.");
    return x.substring(0, 8);
  }

  static String makeBatch(List<Path> events, String cnpj, Path output) throws Exception {
    if (events.isEmpty() || events.size() > 50)
      throw new IllegalArgumentException("Selecione entre 1 e 50 eventos.");
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
    f.setNamespaceAware(true);
    Document d = f.newDocumentBuilder().newDocument();
    String ns = "http://www.dere.gov.br/schemas/envioLoteDere/v1_0_1";
    Element root = d.createElementNS(ns, "DeRE");
    root.setAttribute("xmlns", ns);
    d.appendChild(root);
    Element lote = d.createElementNS(ns, "loteEventos");
    root.appendChild(lote);
    Element ide = d.createElementNS(ns, "ideContrib");
    lote.appendChild(ide);
    Element nr = d.createElementNS(ns, "nrInsc");
    nr.setTextContent(baseCnpj(cnpj));
    ide.appendChild(nr);
    Element evs = d.createElementNS(ns, "eventos");
    lote.appendChild(evs);
    for (Path p : events) {
      validateEvent(p);
      Document ed = parse(p);
      Element wrapper = d.createElementNS(ns, "evento");
      wrapper.setAttribute("id", "evento-" + UUID.randomUUID());
      evs.appendChild(wrapper);
      wrapper.appendChild(d.importNode(ed.getDocumentElement(), true));
    }
    Files.write(output, bytes(d));
    validate(output, "envioLoteDere-v1_0_1.xsd");
    return output.toString();
  }
}

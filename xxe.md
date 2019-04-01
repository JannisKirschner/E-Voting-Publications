# XXE - XML External Entity Processing
---

| Action  | Date  |
|---|---|
| Vulnerability reported  | 08.02.2019  |
| Report closed  | 18.02.2019  |
| Vulnerability fixed  | Next Version (Date NA)  |

Abstract:
Due to an important setting missing in the XML parsing library one could potentially disclose internal files or scan ports.

The following file is affected: 
```
/evoting-solution/source-code/scytl-cryptolib/cryptolib-asymmetric/src/main/java/com/scytl/cryptolib/asymmetric/utils/DomUtils.java
```

The initialization of the TransformerFactory does not prevent access to external stylesheets.
```java
// Write DOM data to output stream.
try {
    TransformerFactory transformerFactory =
        TransformerFactory.newInstance();
    transformerFactory.setAttribute(
        XMLConstants.ACCESS_EXTERNAL_DTD, "");

    Transformer transformer = transformerFactory.newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION,
        "yes");
    transformer.transform(new DOMSource(dom), new StreamResult(
        outStream));
} catch (TransformerException e) {
    throw new GeneralSecurityException(
        DOM_DATA_WRITE_ERROR_MESSAGE, e);
} finally {
    closeQuietly(outStream);
}
```

This line of code would fix the vulnerability:
```java
transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
```

Since there was no running instance of the affected components we weren't able to provide a PoC. 
Given we would have access to it a demo exploit would look something like this:

```java
<?xml-stylesheet type="text/xml" href="http://[IP]"?>
```

| Researchers |
| --- |
| Jannis Kirschner | 
| Anthony Schneiter | 


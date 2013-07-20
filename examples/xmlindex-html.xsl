<?xml version="1.0"?>
<xsl:stylesheet
  version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:html="http://www.w3.org/TR/html4/"
  xmlns="http://www.w3.org/TR/html4/"
  exclude-result-prefixes="html">
  <xsl:output method="html" doctype-public="-//W3C//DTD HTML 4.01 Strict//EN"
    indent="yes" doctype-system="http://www.w3.org/TR/html4/strict.dtd"
    encoding="UTF-8" />

  <xsl:template name="format-date">
    <xsl:param name="date" />

    <xsl:value-of select="substring-before($date, 'T')" />
    <xsl:text> </xsl:text>
    <xsl:value-of select="substring-after($date, 'T')" />
  </xsl:template>

  <xsl:template match="index">
    <html>
    <head>
    <xsl:choose>
      <xsl:when test="$stylesheet">
      <link rel="stylesheet" type="text/css" media="all" href="{$stylesheet}" />
      </xsl:when>
      <xsl:otherwise>
      <style type="text/css">
      html {
        color: #000000;
        background-color: #fefefe;
        font-family: sans-serif;
      }
      h1 {
        font-size: 1.5em;
        font-weight: bold;
        margin: .67em 0;
      }
      th {
        text-align: left;
      }
      td {
        font-family: mono;
      }
      td, th {
        padding: 0 1em;
      }
      td.size {
        text-align: right;
      }
      :link, :visited {
        text-decoration: none;
      }
      :link {
        color: #000099;
      }
      :visited {
        color: #6600cc;
      }
      :link:hover,
      :visited:hover {
        text-decoration: underline;
      }
      :link:focus,
      :visited:focus {
        text-decoration: underline;
      }
      :link:active,
      :visited:active {
        text-decoration: underline;
      }
      </style>
      </xsl:otherwise>
    </xsl:choose>
    <title>Index of <xsl:value-of select="@path" /></title>
    </head>
    <body>
    <h1>Index of <xsl:value-of select="@path" /></h1>
    <table>
    <tr>
    <th class="name">Name</th>
    <th class="mtime">Last Modified</th>
    <th class="size">Size</th>
    </tr>
    <tr>
    <td class="name" colspan="3"><a href=".." title="Parent">Parent directory</a></td>
    </tr>
    <xsl:apply-templates select="directory" />
    <xsl:apply-templates select="file" />
    </table>
    </body>
    </html>
  </xsl:template>

  <xsl:template match="directory">
    <tr class="directory">
    <td class="name">
    <xsl:element name="a">
      <xsl:attribute name="href">
        <xsl:value-of select="." />
        <xsl:text>/</xsl:text>
      </xsl:attribute>
      <xsl:attribute name="title">
        <xsl:value-of select="." />
        <xsl:text>/</xsl:text>
      </xsl:attribute>
      <xsl:value-of select="." />
      <xsl:text>/</xsl:text>
    </xsl:element>
    </td>
    <td class="mtime">
    <xsl:call-template name="format-date">
      <xsl:with-param name="date" select="@mtime" />
    </xsl:call-template>
    </td>
    <td class="size">
    <xsl:value-of select="@size" />
    </td>
    </tr>
  </xsl:template>

  <xsl:template match="file">
    <tr class="file">
    <td class="name">
    <xsl:element name="a">
      <xsl:attribute name="href">
        <xsl:value-of select="." />
      </xsl:attribute>
      <xsl:attribute name="title">
        <xsl:value-of select="." />
      </xsl:attribute>
      <xsl:value-of select="." />
    </xsl:element>
    </td>
    <td class="mtime">
    <xsl:call-template name="format-date">
      <xsl:with-param name="date" select="@mtime" />
    </xsl:call-template>
    </td>
    <td class="size">
    <xsl:value-of select="@size" />
    </td>
    </tr>
  </xsl:template>
</xsl:stylesheet>


<?xml version="1.0"?>

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:import href="CitrixReportStyle.xslt"/>

    <xsl:output method="xml" indent="yes" encoding="UTF-8" doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"
                doctype-public="-//W3C//DTD XHTML 1.0 Strict//EN" />

    <xsl:template match="TestResultData">
        <xsl:call-template name="CitrixReportStyle"/>
    </xsl:template>

    <xsl:template name="CustomStyles">
        <style type="text/css">
            ul {
            list-style-type: none;
            }

            li.Error
            {
            list-style-image: url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAFFJREFUeNpiYBh+4D8DQwIQ92MR7wfJEaP5PxTPRxKfjySegM8AZIX/oXwMMUKuQNdAvGYChmDVzESLWCDfCxQHIsXRiGTIfByuSxiGeQcgwABq7XYnSXRObAAAAABJRU5ErkJggg==");
            }

            li.FatalError
            {
            list-style-image: url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAFFJREFUeNpiYBh+4D8DQwIQ92MR7wfJEaP5PxTPRxKfjySegM8AZIX/oXwMMUKuQNdAvGYChmDVzESLWCDfCxQHIsXRiGTIfByuSxiGeQcgwABq7XYnSXRObAAAAABJRU5ErkJggg==");
            }

            li.Warning
            {
            list-style-image: url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAOlJREFUeNpiYBhowIhL4kuisAKQOg/lGvLMf/sAmzomPIbXA7EAFNeT5AKo7feZ5HTA/H+ProAoRVyuwGbA/h9zcv7DwM9lVf9BYkR5AajQAUg5MHLxwcX+f/sEohygcgTDAOzfvzePwgWQ2PV4DQDakACyCebv/28eQ/EjmBIHqBo4YMFmOxab0dUswHAB0OQCIKWArPL37hkMf44uRzdAAaoWEY1AAVBc34fGOURCRI6BswES8N9ylNEN+QCN1g8wFyQga4YbwsWPQiMBAageeBhgJBBQwH0rM4JG40dsYfGAYVAAgAADAJUgXMgGY/utAAAAAElFTkSuQmCC");
            }

            li.NotRun
            {
            list-style-type:none;
            }

            p.testName
            {
            margin: 0;
            font-weight: bold;
            }

            span.testTargetName
            {
            font-weight: bold;
            }

            span.controllersHdr
            {
            font-weight: bold;
            }

            p.runOnSite
            {
            font-weight: bold;
            }
        </style>
    </xsl:template>

    <xsl:template name="Content">
        <!-- Put some strings into variables so they're globally accessible -->
        <xsl:variable name="testNameHdr" select="@testNameHdr" />
        <xsl:variable name="dateTimeHdr" select="@dateTimeHdr" />
        <xsl:variable name="testResultHdr" select="@testResultHdr" />
        <xsl:variable name="controllersHdr" select="@controllersHdr" />
        <xsl:variable name="serviceHdr" select="@serviceHdr" />
        <xsl:variable name="runOnSiteHdr" select="@runOnSiteHdr" />
        <div>
            <p>
                <xsl:value-of select="@testDescription"/>
            </p>
            <h2 id="createdby">
                <xsl:value-of select="@createdBy" />
            </h2>
            <h3>
                <xsl:value-of select="@reportTime" />
            </h3>
        </div>
        <div class="section">
            <table>
                <colgroup>
                    <col width="60%" />
                    <col width="15%" />
                    <col width="15%" />
                    <col width="10%" />
                </colgroup>
                <tr class="dark darkheader">
                    <th class="first">
                        <xsl:value-of select="$testNameHdr" />
                    </th>
                    <th>
                        <xsl:value-of select="$serviceHdr" />
                    </th>
                    <th>
                        <xsl:value-of select="$dateTimeHdr" />
                    </th>
                    <th class="last">
                        <xsl:value-of select="$testResultHdr" />
                    </th>
                </tr>
                <xsl:for-each select="Test">
                    <tr>
                        <td class="first">
                            <p class="testName">
                                <xsl:value-of select="@shortName" />
                            </p>
                            <xsl:value-of select="@description" />

                            <xsl:choose>
                                <xsl:when test="@testRunOnSite">
                                    <p class="runOnSite">
                                        <xsl:value-of select="$runOnSiteHdr" />
                                    </p>
                                </xsl:when>
                                <xsl:when test="@controllers">
                                    <p>
                                        <span class="controllersHdr">
                                            <xsl:value-of select="$controllersHdr" />
                                        </span>
                                        <xsl:value-of select="@controllers" />
                                    </p>
                                </xsl:when>
                                <xsl:otherwise>
                                </xsl:otherwise>
                            </xsl:choose>

                            <xsl:if test="count(Detail)">
                                <ul>
                                    <xsl:for-each select="Detail">
                                        <li>
                                            <xsl:attribute name="class">
                                                <xsl:value-of select="@severity" />
                                            </xsl:attribute>
                                            <xsl:if test="@target">
                                                <span class="testTargetName">
                                                    <xsl:value-of select="@target" />
                                                </span>
                                            </xsl:if>
                                            <xsl:value-of select="@explanation" />
                                            <xsl:text> </xsl:text>
                                            <!-- single character of whitespace between explanation and comment -->
                                            <xsl:comment>
                                                <xsl:value-of select="@serviceSource" />
                                            </xsl:comment>
                                            <br />
                                            <em>
                                                <xsl:value-of select="@action" disable-output-escaping="yes"/>
                                            </em>
                                        </li>
                                    </xsl:for-each>
                                </ul>
                            </xsl:if>
                        </td>
                        <td>
                            <xsl:value-of select="@service"/>
                        </td>
                        <td>
                            <xsl:value-of select="@dateTime" />
                        </td>
                        <td class="last">
                            <xsl:value-of select="@result" />
                        </td>
                    </tr>
                </xsl:for-each>
            </table>
        </div>
    </xsl:template>
</xsl:stylesheet>
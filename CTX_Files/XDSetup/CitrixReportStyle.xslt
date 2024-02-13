<?xml version="1.0"?>

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="xml" indent="yes" encoding="UTF-8" doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"
              doctype-public="-//W3C//DTD XHTML 1.0 Strict//EN" />
  <xsl:template name="CitrixReportStyle">

    <html xmlns="http://www.w3.org/1999/xhtml">
      <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <title>
          <xsl:value-of select="@mainTitle" />
        </title>
        <style type="text/css">
          body
          {
          background: #ffffff;
          color: #333333;
          font-family: Segoe UI, Tahoma, sans-serif;
          font-size: 12px;
          margin: 0;
          }

          div.section
          {
          margin: 20px 0;
          }

          div#content
          {
          margin: 32px 20px;
          }

          div#titlebar
          {
          background: #5c5f63;
          background-image: url("data:image/png,%89PNG%0D%0A%1A%0A%00%00%00%0DIHDR%00%00%00%01%00%00%004%08%02%00%00%00%C4%C0%C5%C0%00%00%00%01sRGB%00%AE%CE%1C%E9%00%00%00%06bKGD%00%FF%00%FF%00%FF%A0%BD%A7%93%00%00%00%09pHYs%00%00%0B%12%00%00%0B%12%01%D2%DD~%FC%00%00%00%07tIME%07%DC%05%18%09%1F%07%A8%8A%26F%00%00%00KIDAT%08%D7m%8D1%0E%800%0C%03%AF~.%03%03%FFW%8E%A1)%05%89)%8Eu%B69%CE%2BC%A3%841%AF%18%AA%3DLA%D0%08%CD%1A%20%EAd%25%AE%BF3%BC%B4%9D%A5%7BV%1F%12%AD%EE%DA%1B%FE%E4%F7%5Es%8F%F7an2%D5U%5C%22B%94%88%00%00%00%00IEND%AEB%60%82");
          border-top: 1px solid #5b5e62;
          height: 52px;
          padding: 0 20px;
          }

          div#titlebarinner
          {
          width: 100%;
          }

          h1
          {
          color: #1976D2;
          font-size: 24px;
          font-weight: bold;
          margin: 4px 0;
          }

          h2
          {
          font-size: 16px;
          font-weight: bold;
          margin: 4px 0;
          }

          h2#createdby
          {
          font-weight: normal;
          }

          h3
          {
          font-size: inherit;
          font-weight: normal;
          margin: 4px 0;
          }

          img#citrixlogo
          {
          float: right;
          }

          span#topheadertext
          {
          color: #ffffff;
          float: left;
          font-size: 24px;
          font-weight: bold;
          margin: 10px 0;
          }

          table
          {
          border: 1px solid #b3b3b3;
          border-collapse: collapse;
          font-size: inherit;
          width: 100%;
          }

          table.innertable
          {
          border: none;
          width: inherit;
          }

          table.innertable td
          {
          padding: 0 15px;
          }

          table.innertable tr th
          {
          background: inherit;
          border: none;
          height: inherit;
          padding: 0 15px 5px;
          }

          table.innertable tr
          {
          border: none;
          }

          td
          {
          padding: 5px 15px;
          vertical-align: top;
          }

          td.first, th.first
          {
          border-left: 1px solid #b3b3b3;
          }

          th
          {
          border-left: 1px solid #cccccc;
          font-weight: bold;
          height: 32px;
          padding-left: 15px;
          text-align: left;
          }

          td.last, th.last
          {
          border-right: 1px solid #b3b3b3;
          }

          tr
          {
          border-top: 1px solid #eeeeee;
          }

          tr.dark
          {
          color: #ffffff;
          }

          tr.dark td
          {
          background: #999999;
          }

          tr.dark th
          {
          background: #666666;
          }

          tr.dark th.first
          {
          border-left: 1px solid #666666;
          }

          tr.dark th.last
          {
          border-right: 1px solid #666666;
          }

          tr.darkheader
          {
          border-top: 1px solid #666666;
          border-bottom: 1px solid #666666;
          }

          tr.light
          {
          border: 0;
          }

          tr.light td
          {
          background: #eeeeee;
          }

          tr.light th
          {
          background: #cccccc;
          border-left-color: #b3b3b3;
          }

          tr.lightheader
          {
          border-top: 1px solid #cccccc;
          border-bottom: 1px solid #cccccc;
          }

          tr.lightheader th.first
          {
          border-left: 1px solid #cccccc;
          }

          tr.lightheader th.last
          {
          border-right: 1px solid #cccccc;
          }

          tr.lightsubheader td
          {
          font-weight: bold;
          }

          .indented
          {
          padding-left: 40px;
          }
        </style>
        <xsl:call-template name="CustomStyles"/>
      </head>
      <body>
        <div id="titlebar">
          <div id="titlebarinner">
            <span id="topheadertext">
              <xsl:value-of select="@mainTitle" />
            </span>
            <img id="citrixlogo" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAAA0CAYAAAA62j4JAAAAAXNSR0IArs4c6QAABFlJREFUaEPtmFvIZWMYx39/cSPjcINpnEJDuFDGhclpSCSMiUFCZhzGMUlKymkkoZDkMI4XxmkSihlzw4QZh7gxYpCcBuFCDkWkv57du3Zrr73W3vv71rf37Nrrvdrft971vs/zf/7/57DEhC9NuP80ADQMmHAEGglMOAGaJNhIoJHAhCPQSGDCCdBUgUYCjQRqImB7LvA2sF7Souw42xcDDwMLJK2rec1Ar9v+GPgFOEXSH4O8VFsCtt8Ajk6XtZ21fTNw06gAyN0XpgwM+kwAcDDwIrBO0pIcA0YKQNybghE/T5b050gYUHXJqBkwiLNleyoZYHsvYBdgs6Tvp3rBVAGwPQfYDfha0k/5+2zvKembqdowyP4OAGyfB0TyOgDYKXfARuBp4P4yatn+ANhYIYGiHUskPZlLkvOBO4Ajchs/ApZK+tD2MuAhYF78nai+GLgTuELSq70ctX0dcDvQure4tw2A7WeAs9KGx4D3gZ+Bo1KSC63/ACyWtKEQIaccsKAkBxQrwF2SVheSVry2CvgkgR9J9XJJq2yH8eHESZmzto8HXgN+BY7LgCk6Zzv8Cb8+S4nxx1IAbAeiz6eHkUBeKTnsAeDS9P8dJf2Wc7YXAKUZuQDAOZJWlkWyDIDEgrAlbPoUOFZSh3O25wFvAX8BCyXF764l26G779KTnSVFHS1dtt9MVF0hKajZWrbrAPC4pAt63NnFgNy9UWaj2kQFyrNve+A9YH/gdEkvVJ0fAISWrk2UC0Qrl+39Um3/XFJcPBMALJO0YjoAJPAzZj4nqSVh22uAEwbxKQCIJHIisK+kL3sB0MPIOgzo2bRUSSAH/lZJvqcBdwPbAFcCyyUFQ3quAOCreElSSGFaq6YEagGQIj47gXB4cqBDor2cCgCiZ94k6dBpeV8/B9QGIIFwPXAb8C9whqSXBvEnAFgfNRaYJemfQV4q7hkDBmSD17fJtq0TCOFbXwk8AlwIzJf0Tr8XbF8mqSNZbkkAbMcEGj3Ef8CRyf6oVptSBfiinwQy9J6SdG6vzbbPB54AbpnBKjBtCdiOLjJK3K7AqZJeTnJYCIQEXgcWSfq9yq9WJ5ha2UOAsyVF59S1bEd7HBUjZoQOo7cEA2zvk5w8KBo0SdEut5ftS4AHgXZ5LPMrA2APIBs27o0oS4p+vLVSpxgl5cBi9NPzkZZB29sBEe1jgFsl3VgRtOXADcB9kq6qBCA5sQNwTwwNaWNMZJuBvdNg9HcMLXnq5wAaJgBR268uzALRtkf7/qiki/rINstxMVu0cpftw4AI+rZd47DtM1O7G9NZ0D0S47vASkmlCcV2TIrF7jCaq+gwI190fRKznT2PPr1So7aDdddIWpoDPLrQGJHbH2D6gBB561lJaxMAu6ekObf2F6F+VWPcnzcAjHuEhm1fw4BhIzzu5zcMGPcIDdu+hgHDRnjcz28YMO4RGrZ9DQOGjfC4n98wYNwjNGz7Jp4B/wOfE3zu5HvFJwAAAABJRU5ErkJggg=="/>
          </div>
        </div>
        <div id="content">
          <xsl:call-template name="Content"/>
        </div>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
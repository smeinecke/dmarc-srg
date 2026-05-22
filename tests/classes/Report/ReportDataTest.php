<?php

namespace Liuch\DmarcSrg\Report;

use Liuch\DmarcSrg\Exception\SoftException;

class ReportDataTest extends \PHPUnit\Framework\TestCase
{
    private static function minimalValidXml(): string
    {
        return '<?xml version="1.0" encoding="UTF-8" ?>'
            . '<feedback>'
            . '<report_metadata>'
            . '<org_name>Example Org</org_name>'
            . '<email>postmaster@example.com</email>'
            . '<report_id>12345</report_id>'
            . '<date_range><begin>1609459200</begin><end>1609545600</end></date_range>'
            . '</report_metadata>'
            . '<policy_published>'
            . '<domain>example.com</domain>'
            . '<adkim>r</adkim>'
            . '<aspf>r</aspf>'
            . '<p>none</p>'
            . '<sp>none</sp>'
            . '<pct>100</pct>'
            . '</policy_published>'
            . '<record>'
            . '<row>'
            . '<source_ip>192.0.2.1</source_ip>'
            . '<count>1</count>'
            . '<policy_evaluated>'
            . '<disposition>none</disposition>'
            . '<dkim>pass</dkim>'
            . '<spf>pass</spf>'
            . '</policy_evaluated>'
            . '</row>'
            . '<identifiers>'
            . '<header_from>example.com</header_from>'
            . '</identifiers>'
            . '<auth_results>'
            . '<dkim><domain>example.com</domain><result>pass</result></dkim>'
            . '<spf><domain>example.com</domain><result>pass</result></spf>'
            . '</auth_results>'
            . '</record>'
            . '</feedback>';
    }

    private function generateXml(int $record_count)
    {
        $xml = '<?xml version="1.0" encoding="UTF-8" ?>';
        $xml .= '<feedback>';
        $xml .= '<report_metadata>';
        $xml .= '<org_name>example.com</org_name>';
        $xml .= '<email>r@example.com</email>';
        $xml .= '<report_id>123</report_id>';
        $xml .= '<date_range><begin>1609459200</begin><end>1609545600</end></date_range>';
        $xml .= '</report_metadata>';
        $xml .= '<policy_published>';
        $xml .= '<domain>example.com</domain>';
        $xml .= '<p>none</p>';
        $xml .= '</policy_published>';
        for ($i = 0; $i < $record_count; ++$i) {
            $xml .= '<record>';
            $xml .= '<row><source_ip>192.0.2.1</source_ip><count>1</count></row>';
            $xml .= '<identifiers><header_from>example.com</header_from></identifiers>';
            $xml .= '<auth_results><dkim><domain>example.com</domain><result>pass</result></dkim></auth_results>';
            $xml .= '</record>';
        }
        $xml .= '</feedback>';

        $fd = fopen('php://memory', 'r+');
        fwrite($fd, $xml);
        rewind($fd);
        return $fd;
    }

    public function testFromXmlFileValid(): void
    {
        $xml = self::minimalValidXml();
        $fd = fopen('php://memory', 'r+');
        fwrite($fd, $xml);
        rewind($fd);

        $data = ReportData::fromXmlFile($fd);
        fclose($fd);

        $this->assertTrue($data->isValid());
    }

    public function testFromXmlFileUnderLimit(): void
    {
        $xml = self::minimalValidXml();
        $fd = fopen('php://memory', 'r+');
        fwrite($fd, $xml);
        rewind($fd);

        $data = ReportData::fromXmlFile($fd, false, 1024 * 1024);
        fclose($fd);

        $this->assertTrue($data->isValid());
    }

    public function testFromXmlFileExceedsLimit(): void
    {
        $xml = self::minimalValidXml();
        $fd = fopen('php://memory', 'r+');
        fwrite($fd, $xml);
        rewind($fd);

        $this->expectException(SoftException::class);
        $this->expectExceptionMessage('Report file is too large after decompression');

        ReportData::fromXmlFile($fd, false, strlen($xml) - 1);
    }

    public function testFromXmlFileNoLimit(): void
    {
        $xml = self::minimalValidXml();
        $fd = fopen('php://memory', 'r+');
        fwrite($fd, $xml);
        rewind($fd);

        $data = ReportData::fromXmlFile($fd, false, null);
        fclose($fd);

        $this->assertTrue($data->isValid());
    }

    public function testFromXmlFileWithRecordsBelowLimit(): void
    {
        $fd = $this->generateXml(2);
        $data = ReportData::fromXmlFile($fd, false, null, 5);
        $this->assertCount(2, $data->toArray()['records']);
        fclose($fd);
    }

    public function testFromXmlFileWithRecordsAtLimit(): void
    {
        $fd = $this->generateXml(3);
        $data = ReportData::fromXmlFile($fd, false, null, 3);
        $this->assertCount(3, $data->toArray()['records']);
        fclose($fd);
    }

    public function testFromXmlFileWithRecordsAboveLimit(): void
    {
        $fd = $this->generateXml(3);
        $this->expectException(SoftException::class);
        $this->expectExceptionMessage('Too many records');
        ReportData::fromXmlFile($fd, false, null, 2);
        fclose($fd);
    }

    public function testFromXmlFileWithLimitZeroIsUnlimited(): void
    {
        $fd = $this->generateXml(5);
        $data = ReportData::fromXmlFile($fd, false, null, 0);
        $this->assertCount(5, $data->toArray()['records']);
        fclose($fd);
    }
}

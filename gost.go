package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	_ "github.com/maxyotka/gost-crypto"
)

// Описываем структуру времени в сертификате (UTCTime или GeneralizedTime)
type Validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// Упрощенная структура сертификата для поиска дат
type RawCertificate struct {
	Raw                asn1.RawContent
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	SignatureValue     asn1.BitString
}

type TBSCertificate struct {
	Raw                asn1.RawContent
	Version            asn1.RawValue `asn1:"optional,explicit,tag:0"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Issuer             asn1.RawValue
	Validity           Validity
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	// Остальные поля (extensions) игнорируем для скорости
}

func Connect(ctx context.Context, target string, port string) (*x509.Certificate, error) {

	// 1. Формируем тело ClientHello
	handshakeBody := makeClientHello(target)

	// 2. Оборачиваем в TLS Record Header
	record := make([]byte, 5)
	record[0] = 0x16 // Content Type: Handshake (22)
	record[1] = 0x03 // Legacy Record Layer Version (3.x)
	record[2] = 0x03 // 3.3 = TLS 1.2
	binary.BigEndian.PutUint16(record[3:], uint16(len(handshakeBody)))

	fullPacket := append(record, handshakeBody...)

	// 3. Отправляем в сокет
	// conn, err := net.DialTimeout("tcp", target+":"+port, 5*time.Second)
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", target+":"+port)
	if err != nil {
		return nil, fmt.Errorf("Ошибка подключения: %v\n", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	slog.Debug("sending ClientHello", "target", target, "size", len(fullPacket))
	conn.Write(fullPacket)

	var fullResponse []byte
	for {
		record, err := readFullRecord(ctx, conn)
		if err != nil {
			return nil, err
		}
		fullResponse = append(fullResponse, record...)

		// Если в накопленных данных уже есть сообщение Certificate (0x0b)
		// и мы прочитали его полностью (сверяем по msgLen) — выходим из цикла
		if o, _, err := findCertificateOffset(fullResponse); err == nil {
			// Маленькая проверка: достаточно ли данных для парсинга msgLen?
			if len(fullResponse) > o+4 {
				msgLen := int(fullResponse[o+1])<<16 | int(fullResponse[o+2])<<8 | int(fullResponse[o+3])
				if len(fullResponse) >= o+4+msgLen {
					break // Всё прочитано!
				}
			}
		}

		// Предохранитель, чтобы не зависнуть вечно
		if len(fullResponse) > 32768 {
			return nil, fmt.Errorf("response too long")
		}
	}

	res := fullResponse

	slog.Debug("server response received", "target", target, "size", len(fullResponse), "first_bytes", fmt.Sprintf("%x", res[:5]))

	if res[0] == 0x16 {
		slog.Debug("server accepted ClientHello", "target", target)
	} else if res[0] == 0x15 {
		return nil, fmt.Errorf("server returned TLS Alert")
	}
	o, s, err := findCertificateOffset(res)
	if err != nil {
		return nil, fmt.Errorf("certificate not found")
	}
	slog.Debug("certificate found", "target", target, "offset", o, "size", s)

	// Пропускаем 4 байта (тип 0x0b + 3 байта длины сообщения)
	certData := res[o+4:]
	// Внутри сообщения Certificate сначала идет 3 байта - суммарная длина цепочки.
	// А за ней еще 3 байта - длина ПЕРВОГО сертификата.
	firstCertLen := int(certData[3])<<16 | int(certData[4])<<8 | int(certData[5])
	// Вот теперь у нас есть чистый DER первого сертификата
	firstCertDER := certData[6 : 6+firstCertLen]
	slog.Debug("certificate DER parsed", "target", target, "size", len(firstCertDER))

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled before parsing: %w", err)
	}

	// Вызываем парсер, который мы обсуждали ранее
	// tbs, err := parseGostCertificate(firstCertDER)
	// if err != nil {
	// 	fmt.Printf("Ошибка: %s", err)
	// }

	cert, err := x509.ParseCertificate(firstCertDER)
	if err != nil {
		return nil, fmt.Errorf("Ошибка x509: %v", err)
	}

	return cert, nil
}

func findCertificateOffset(raw []byte) (offset int, size int, err error) {
	for idx := 0; idx < len(raw); idx = idx + 1 {
		if raw[idx] == 0x0b {
			msgLen := int(raw[idx+1])<<16 | int(raw[idx+2])<<8 | int(raw[idx+3])
			return idx, msgLen, nil
		}
	}
	return 0, 0, fmt.Errorf("Not found")
}

func makeClientHello(hostname string) []byte {
	var b bytes.Buffer

	// Handshake Type: Client Hello (1)
	b.WriteByte(0x01)
	// Длина (заполним позже)
	b.Write([]byte{0x00, 0x00, 0x00})

	// Version TLS 1.2
	b.Write([]byte{0x03, 0x03})

	// Random (32 bytes: 4 unix time + 28 random)
	b.Write(make([]byte, 32))

	// Session ID (0)
	b.WriteByte(0x00)

	// Cipher Suites
	// 0xc1, 0x01 - TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC
	// 0xc1, 0x02 - TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC
	cipherSuites := []byte{0xc1, 0x01, 0xc1, 0x02}
	binary.Write(&b, binary.BigEndian, uint16(len(cipherSuites)))
	b.Write(cipherSuites)

	// Compression Methods (0 - null)
	b.Write([]byte{0x01, 0x00})

	// Extensions (SNI обязательно для ГОСТ-ресурсов)
	var ext bytes.Buffer
	// Server Name Extension
	ext.Write([]byte{0x00, 0x00}) // Type SNI

	var sni bytes.Buffer
	sni.WriteByte(0x00) // Name Type: host_name (0)
	binary.Write(&sni, binary.BigEndian, uint16(len(hostname)))
	sni.WriteString(hostname)

	var sniWrapper bytes.Buffer
	binary.Write(&sniWrapper, binary.BigEndian, uint16(sni.Len()))
	sniWrapper.Write(sni.Bytes())

	binary.Write(&ext, binary.BigEndian, uint16(sniWrapper.Len()))
	ext.Write(sniWrapper.Bytes())

	// Пишем общую длину расширений
	binary.Write(&b, binary.BigEndian, uint16(ext.Len()))
	b.Write(ext.Bytes())

	// Фиксируем длину тела Handshake
	res := b.Bytes()
	length := len(res) - 4
	res[1] = byte(length >> 16)
	res[2] = byte(length >> 8)
	res[3] = byte(length)

	return res
}

func parseGostCertificate(der []byte) (*TBSCertificate, error) {
	var cert RawCertificate
	_, err := asn1.Unmarshal(der, &cert)
	if err != nil {
		return nil, fmt.Errorf("Ошибка первичного парсинга: %v\n", err)
	}

	var tbs TBSCertificate
	_, err = asn1.Unmarshal(cert.TBSCertificate.FullBytes, &tbs)
	if err != nil {
		return nil, fmt.Errorf("Ошибка парсинга TBS секции: %v\n", err)
	}
	return &tbs, nil
}

func readFullRecord(ctx context.Context, conn net.Conn) ([]byte, error) {
	// Периодическая проверка контекста
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 1. Читаем строго 5 байт заголовка TLS Record
	header := make([]byte, 5)
	_, err := io.ReadFull(conn, header)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS header: %v", err)
	}

	// 2. Проверяем тип (должен быть Handshake 0x16 или Alert 0x15)
	if header[0] == 0x15 {
		return nil, fmt.Errorf("server sent TLS Alert")
	}
	if header[0] != 0x16 {
		return nil, fmt.Errorf("unexpected record type: %x", header[0])
	}

	// 3. Узнаем длину тела из байтов [3:5]
	recordLen := binary.BigEndian.Uint16(header[3:])
	if recordLen > 16384 { // Защита от кривых данных
		return nil, fmt.Errorf("record too large: %d", recordLen)
	}

	// 4. Дочитываем ровно recordLen байт
	body := make([]byte, recordLen)
	_, err = io.ReadFull(conn, body)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS body: %v", err)
	}

	// Возвращаем полный пакет (заголовок + тело)
	return append(header, body...), nil
}

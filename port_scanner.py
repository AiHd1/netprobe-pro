#!/usr/bin/env python3
"""
NetProbe Pro - Advanced Port Scanner
Автор: [Твоё имя]
Версия: 1.0
"""

import socket
import concurrent.futures
import json
import csv
import datetime
import sys
import ipaddress
from typing import Optional

# База данных опасных портов с объяснениями
DANGEROUS_PORTS = {
    21: {"service": "FTP", "risk": "HIGH", "reason": "Передача файлов без шифрования"},
    22: {"service": "SSH", "risk": "MEDIUM", "reason": "Брутфорс атаки если слабый пароль"},
    23: {"service": "Telnet", "risk": "CRITICAL", "reason": "Полностью незашифрованный протокол"},
    25: {"service": "SMTP", "risk": "HIGH", "reason": "Может использоваться для спама"},
    53: {"service": "DNS", "risk": "MEDIUM", "reason": "DNS amplification атаки"},
    80: {"service": "HTTP", "risk": "MEDIUM", "reason": "Незашифрованный веб-трафик"},
    110: {"service": "POP3", "risk": "HIGH", "reason": "Почта без шифрования"},
    135: {"service": "RPC", "risk": "HIGH", "reason": "Часто атакуется в Windows"},
    139: {"service": "NetBIOS", "risk": "HIGH", "reason": "Утечка информации о сети"},
    143: {"service": "IMAP", "risk": "HIGH", "reason": "Почта без шифрования"},
    443: {"service": "HTTPS", "risk": "LOW", "reason": "Зашифрованный веб — OK"},
    445: {"service": "SMB", "risk": "CRITICAL", "reason": "WannaCry и другие атаки"},
    1433: {"service": "MSSQL", "risk": "CRITICAL", "reason": "База данных открыта наружу"},
    1521: {"service": "Oracle DB", "risk": "CRITICAL", "reason": "База данных открыта наружу"},
    3306: {"service": "MySQL", "risk": "CRITICAL", "reason": "База данных открыта наружу"},
    3389: {"service": "RDP", "risk": "CRITICAL", "reason": "Удалённый рабочий стол — частая цель"},
    5432: {"service": "PostgreSQL", "risk": "CRITICAL", "reason": "База данных открыта наружу"},
    5900: {"service": "VNC", "risk": "HIGH", "reason": "Удалённый доступ к экрану"},
    6379: {"service": "Redis", "risk": "CRITICAL", "reason": "Часто без пароля"},
    8080: {"service": "HTTP-alt", "risk": "MEDIUM", "reason": "Альтернативный веб-порт"},
    8443: {"service": "HTTPS-alt", "risk": "LOW", "reason": "Альтернативный HTTPS"},
    27017: {"service": "MongoDB", "risk": "CRITICAL", "reason": "База данных часто без пароля"},
}

COMMON_PORTS = list(range(1, 1025)) + [
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017, 27018
]


def validate_target(target: str) -> Optional[str]:
    """Проверяет что цель валидна — IP или домен"""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """Сканирует один порт"""
    result = {"port": port, "open": False, "service": "unknown", "risk": "UNKNOWN", "reason": ""}
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        connection = sock.connect_ex((host, port))
        
        if connection == 0:
            result["open"] = True
            # Попытка получить баннер
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                result["banner"] = banner[:100] if banner else ""
            except:
                result["banner"] = ""
            
            # Информация об опасности
            if port in DANGEROUS_PORTS:
                info = DANGEROUS_PORTS[port]
                result["service"] = info["service"]
                result["risk"] = info["risk"]
                result["reason"] = info["reason"]
            else:
                try:
                    result["service"] = socket.getservbyport(port)
                    result["risk"] = "LOW"
                except:
                    result["service"] = "unknown"
                    result["risk"] = "UNKNOWN"
        
        sock.close()
    except Exception:
        pass
    
    return result


def scan_host(target: str, ports: list = None, threads: int = 100, timeout: float = 1.0) -> dict:
    """Главная функция сканирования"""
    
    if ports is None:
        ports = COMMON_PORTS
    
    ip = validate_target(target)
    if not ip:
        return {"error": f"Невозможно разрешить хост: {target}"}
    
    print(f"\n🔍 NetProbe Pro — Сканирование {target} ({ip})")
    print(f"📊 Портов для проверки: {len(ports)}")
    print(f"⚡ Потоков: {threads}\n")
    
    start_time = datetime.datetime.now()
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            result = future.result()
            if result["open"]:
                open_ports.append(result)
                risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(result["risk"], "⚪")
                print(f"  {risk_emoji} Порт {result['port']:5d} | {result['service']:12s} | {result['risk']:8s} | {result['reason']}")
            
            # Прогресс
            if completed % 100 == 0:
                print(f"  ⏳ Прогресс: {completed}/{len(ports)}")
    
    end_time = datetime.datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    # Подсчёт рисков
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for p in open_ports:
        risk_counts[p["risk"]] = risk_counts.get(p["risk"], 0) + 1
    
    # Итоговая оценка
    if risk_counts["CRITICAL"] > 0:
        overall = "КРИТИЧЕСКИЙ"
    elif risk_counts["HIGH"] > 2:
        overall = "ВЫСОКИЙ"
    elif risk_counts["HIGH"] > 0 or risk_counts["MEDIUM"] > 3:
        overall = "СРЕДНИЙ"
    else:
        overall = "НИЗКИЙ"
    
    report = {
        "target": target,
        "ip": ip,
        "scan_date": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": round(duration, 2),
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "risk_summary": risk_counts,
        "overall_risk": overall,
        "recommendations": generate_recommendations(open_ports)
    }
    
    return report


def generate_recommendations(open_ports: list) -> list:
    """Генерирует рекомендации по безопасности"""
    recommendations = []
    
    for port_info in open_ports:
        port = port_info["port"]
        risk = port_info["risk"]
        
        if port == 23:
            recommendations.append("⛔ ОТКЛЮЧИТЕ Telnet немедленно — используйте SSH вместо него")
        elif port == 21:
            recommendations.append("⚠️  FTP открыт — рассмотрите переход на SFTP (порт 22)")
        elif port == 3389:
            recommendations.append("🔒 RDP открыт — ограничьте доступ по IP или используйте VPN")
        elif port in [3306, 5432, 1433, 27017, 6379]:
            recommendations.append(f"🗄️  База данных ({port_info['service']}) открыта наружу — ЗАКРОЙТЕ немедленно")
        elif port == 445:
            recommendations.append("🛡️  SMB открыт — обновите Windows и ограничьте доступ")
        elif port == 80 and any(p["port"] == 443 for p in open_ports):
            recommendations.append("🔀 HTTP и HTTPS оба открыты — перенаправьте весь трафик на HTTPS")
    
    if not recommendations:
        recommendations.append("✅ Явных критических проблем не обнаружено")
    
    return recommendations


def save_report_json(report: dict, filename: str = None):
    """Сохраняет отчёт в JSON"""
    if not filename:
        filename = f"report_{report['target']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n💾 JSON отчёт сохранён: {filename}")
    return filename


def save_report_csv(report: dict, filename: str = None):
    """Сохраняет отчёт в CSV"""
    if not filename:
        filename = f"report_{report['target']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["port", "service", "risk", "reason", "banner"])
        writer.writeheader()
        for port in report["open_ports"]:
            writer.writerow({
                "port": port["port"],
                "service": port["service"],
                "risk": port["risk"],
                "reason": port["reason"],
                "banner": port.get("banner", "")
            })
    print(f"💾 CSV отчёт сохранён: {filename}")
    return filename


def print_summary(report: dict):
    """Красивый итоговый отчёт в терминале"""
    print("\n" + "="*60)
    print("📋 ИТОГОВЫЙ ОТЧЁТ NetProbe Pro")
    print("="*60)
    print(f"🎯 Цель:          {report['target']} ({report['ip']})")
    print(f"📅 Дата:          {report['scan_date']}")
    print(f"⏱️  Время:          {report['duration_seconds']} сек")
    print(f"🔍 Портов проверено: {report['ports_scanned']}")
    print(f"🚪 Открытых портов:  {report['open_count']}")
    print()
    print("📊 РИСКИ:")
    print(f"  🔴 КРИТИЧЕСКИХ: {report['risk_summary'].get('CRITICAL', 0)}")
    print(f"  🟠 ВЫСОКИХ:     {report['risk_summary'].get('HIGH', 0)}")
    print(f"  🟡 СРЕДНИХ:     {report['risk_summary'].get('MEDIUM', 0)}")
    print(f"  🟢 НИЗКИХ:      {report['risk_summary'].get('LOW', 0)}")
    print()
    print(f"⚡ ОБЩИЙ УРОВЕНЬ РИСКА: {report['overall_risk']}")
    print()
    print("💡 РЕКОМЕНДАЦИИ:")
    for rec in report["recommendations"]:
        print(f"  {rec}")
    print("="*60)


# =================== ЗАПУСК ===================
if __name__ == "__main__":
    print("""
╔═══════════════════════════════════════╗
║       NetProbe Pro v1.0               ║
║   Профессиональный сканер портов      ║
╚═══════════════════════════════════════╝
    """)
    
    # Получить цель
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Введите IP или домен для сканирования: ").strip()
    
    if not target:
        print("❌ Ошибка: не указана цель")
        sys.exit(1)
    
    # Запуск сканирования
    report = scan_host(target)
    
    if "error" in report:
        print(f"❌ {report['error']}")
        sys.exit(1)
    
    # Вывод результатов
    print_summary(report)
    
    # Сохранение
    save_report_json(report)
    save_report_csv(report)
    
    print("\n✅ Сканирование завершено!")

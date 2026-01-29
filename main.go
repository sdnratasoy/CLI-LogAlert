package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
	"gopkg.in/yaml.v3"
)


type Rule struct {
	Name     string   `yaml:"name" json:"name"`
	Pattern  string   `yaml:"pattern" json:"pattern"`
	Severity string   `yaml:"severity" json:"severity"`
	LogTypes []string `yaml:"log_types" json:"log_types"`
	Enabled  bool     `yaml:"enabled" json:"enabled"`
}

type Config struct {
	Rules    []Rule   `yaml:"rules" json:"rules"`
	Settings Settings `yaml:"settings" json:"settings"`
}

type Settings struct {
	OutputPath string `yaml:"output_path" json:"output_path"`
}

type Match struct {
	Timestamp string
	File      string
	Line      int
	RuleName  string
	Severity  string
	Matched   string
	IP        string
	Message   string
}


var (
	titleC   = color.New(color.FgCyan, color.Bold)
	successC = color.New(color.FgGreen)
	errorC   = color.New(color.FgRed)
	warnC    = color.New(color.FgYellow)
	infoC    = color.New(color.FgWhite)
	promptC  = color.New(color.FgMagenta)
	critC    = color.New(color.FgRed, color.Bold)
)


func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return defaultConfig(), nil
	}

	cfg := &Config{}
	ext := strings.ToLower(filepath.Ext(path))

	if ext == ".json" {
		err = json.Unmarshal(data, cfg)
	} else {
		err = yaml.Unmarshal(data, cfg)
	}

	if err != nil {
		return defaultConfig(), nil
	}
	if cfg.Settings.OutputPath == "" {
		cfg.Settings.OutputPath = "./reports"
	}
	return cfg, nil
}

func defaultConfig() *Config {
	return &Config{
		Rules: []Rule{
			{Name: "SSH Failed Login", Pattern: `[Ff]ailed password|authentication failure`, Severity: "high", LogTypes: []string{"auth.log", "secure"}, Enabled: true},
			{Name: "Invalid User", Pattern: `[Ii]nvalid user|unknown user`, Severity: "medium", LogTypes: []string{"auth.log", "secure"}, Enabled: true},
			{Name: "SSH Brute Force", Pattern: `maximum authentication attempts`, Severity: "critical", LogTypes: []string{"auth.log", "secure"}, Enabled: true},
			{Name: "Error Detection", Pattern: `[Ee]rror|ERROR|FATAL|[Ff]atal`, Severity: "medium", LogTypes: []string{"syslog", "messages", "nginx"}, Enabled: true},
			{Name: "Firewall Block", Pattern: `UFW BLOCK|iptables.*DROP|DENY`, Severity: "medium", LogTypes: []string{"ufw.log", "firewall"}, Enabled: true},
			{Name: "HTTP 4xx/5xx", Pattern: `" [45]\d{2} `, Severity: "medium", LogTypes: []string{"access.log", "nginx"}, Enabled: true},
			{Name: "SSH Connection", Pattern: `Accepted password|Accepted publickey|session opened`, Severity: "low", LogTypes: []string{"auth.log", "secure"}, Enabled: true},
			{Name: "Sudo Usage", Pattern: `sudo:.*COMMAND=|sudo:.*authentication failure`, Severity: "medium", LogTypes: []string{"auth.log", "secure"}, Enabled: true},
			{Name: "Disk Full", Pattern: `[Nn]o space left|[Dd]isk full`, Severity: "critical", LogTypes: []string{"syslog", "messages"}, Enabled: true},
			{Name: "Windows Failed Login", Pattern: `Event ID: (4625|4771)`, Severity: "high", LogTypes: []string{"windows", "Security.evtx"}, Enabled: true},
		},
		Settings: Settings{OutputPath: "./reports"},
	}
}


func analyzeFile(path string, cfg *Config) ([]Match, int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("dosya acilamadi: %w", err)
	}
	defer file.Close()

	fileName := filepath.Base(path)
	var matches []Match
	totalLines := 0

	type compiled struct {
		rule Rule
		re   *regexp.Regexp
	}
	var rules []compiled
	for _, r := range cfg.Rules {
		if !r.Enabled {
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			continue
		}
		rules = append(rules, compiled{rule: r, re: re})
	}

	ipRe := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	tsRe := regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})`)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		totalLines++

		for _, r := range rules {
			matched := r.re.FindString(line)
			if matched == "" {
				continue
			}

			ip := ""
			if m := ipRe.FindString(line); m != "" {
				ip = m
			}
			ts := ""
			if m := tsRe.FindStringSubmatch(line); len(m) > 1 {
				ts = m[1]
			}

			matches = append(matches, Match{
				Timestamp: ts,
				File:      fileName,
				Line:      totalLines,
				RuleName:  r.rule.Name,
				Severity:  r.rule.Severity,
				Matched:   matched,
				IP:        ip,
				Message:   line,
			})
		}
	}

	return matches, totalLines, scanner.Err()
}


func tailFile(ctx context.Context, path string, cfg *Config) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("dosya acilamadi: %w", err)
	}
	defer file.Close()

	file.Seek(0, io.SeekEnd)

	type compiled struct {
		rule Rule
		re   *regexp.Regexp
	}
	var rules []compiled
	for _, r := range cfg.Rules {
		if !r.Enabled {
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			continue
		}
		rules = append(rules, compiled{rule: r, re: re})
	}

	ipRe := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	reader := bufio.NewReader(file)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}

				for _, r := range rules {
					if matched := r.re.FindString(line); matched != "" {
						ip := ipRe.FindString(line)

						sevColor := getSevColor(r.rule.Severity)
						sevColor.Printf("[%s] ", strings.ToUpper(r.rule.Severity))
						warnC.Printf("%s ", r.rule.Name)
						if ip != "" {
							infoC.Printf("(IP: %s)", ip)
						}
						fmt.Println()
						infoC.Printf("  %s\n\n", line)
					}
				}
			}
		}
	}
}


func saveCSV(matches []Match, outputDir string) (string, error) {
	os.MkdirAll(outputDir, 0755)

	fileName := fmt.Sprintf("rapor_%s.csv", time.Now().Format("20060102_150405"))
	path := filepath.Join(outputDir, fileName)

	file, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Timestamp", "Dosya", "Satir", "Kural", "Severity", "Eslesen", "IP", "Mesaj"})

	for _, m := range matches {
		writer.Write([]string{
			m.Timestamp, m.File, fmt.Sprintf("%d", m.Line),
			m.RuleName, m.Severity, m.Matched, m.IP, m.Message,
		})
	}

	return path, nil
}


func getSevColor(sev string) *color.Color {
	switch sev {
	case "critical":
		return critC
	case "high":
		return warnC
	case "medium":
		return color.New(color.FgCyan)
	case "low":
		return successC
	default:
		return infoC
	}
}

func readInput(reader *bufio.Reader, prompt string) string {
	promptC.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func waitEnter(reader *bufio.Reader) {
	promptC.Print("\nDevam etmek icin Enter'a basin...")
	reader.ReadString('\n')
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}


func main() {
	configPath := "configs/rules.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, _ := loadConfig(configPath)
	reader := bufio.NewReader(os.Stdin)
	var lastMatches []Match

	clearScreen()

	titleC.Println(`
╔═════════════════════════════════════════════╗
║                                             ║
║    LOG ANALIZ VE UYARI ARACI                ║
║    CLI Tabanlı Log Analiz Sistemi           ║
║                                             ║
╚═════════════════════════════════════════════╝`)

	for {
		fmt.Println()
		titleC.Println("═══════════════════════════════════════")
		titleC.Println("              ANA MENU")
		titleC.Println("═══════════════════════════════════════")
		fmt.Println()
		infoC.Println("  1. Log Dosyasi Analiz Et")
		infoC.Println("  2. Gercek Zamanli Izleme (Tail)")
		infoC.Println("  3. Kurallari Goruntule")
		infoC.Println("  4. CSV Rapor Olustur")
		infoC.Println("  5. Cikis")
		fmt.Println()

		choice := readInput(reader, "Seciminiz [1-5]: ")

		switch choice {
		case "1":
			menuAnalyze(reader, cfg, &lastMatches)
		case "2":
			menuTail(reader, cfg)
		case "3":
			menuRules(reader, cfg)
		case "4":
			menuReport(reader, cfg, lastMatches)
		case "5":
			successC.Println("\nGule gule!")
			return
		default:
			errorC.Println("Gecersiz secim!")
		}
	}
}

func menuAnalyze(reader *bufio.Reader, cfg *Config, lastMatches *[]Match) {
	clearScreen()
	titleC.Println("\n═══ LOG DOSYASI ANALIZI ═══\n")

	path := readInput(reader, "Log dosyasi yolu (ornek: samples/auth.log): ")
	if path == "" {
		return
	}

	start := time.Now()
	matches, totalLines, err := analyzeFile(path, cfg)
	duration := time.Since(start)

	if err != nil {
		errorC.Printf("Hata: %v\n", err)
		waitEnter(reader)
		return
	}

	*lastMatches = matches

	clearScreen()
	titleC.Println("═══════════════════════════════════════════════")
	titleC.Println("              LOG ANALIZ RAPORU")
	titleC.Println("═══════════════════════════════════════════════")
	fmt.Println()
	infoC.Printf("  Dosya        : %s\n", path)
	infoC.Printf("  Toplam Satir : %d\n", totalLines)
	infoC.Printf("  Eslesen      : %d\n", len(matches))
	infoC.Printf("  Sure         : %v\n", duration.Round(time.Millisecond))

	ruleCount := map[string]int{}
	ruleSev := map[string]string{}
	ipCount := map[string]int{}

	for _, m := range matches {
		ruleCount[m.RuleName]++
		ruleSev[m.RuleName] = m.Severity
		if m.IP != "" {
			ipCount[m.IP]++
		}
	}

	fmt.Println()
	titleC.Println("  KURAL ESLEME OZETI:")
	titleC.Println("  ┌─────────────────────────────┬──────────┬──────────┐")
	titleC.Println("  │ Kural                       │ Eslesme  │ Severity │")
	titleC.Println("  ├─────────────────────────────┼──────────┼──────────┤")

	for name, count := range ruleCount {
		sev := ruleSev[name]
		sevC := getSevColor(sev)
		displayName := name
		if len(displayName) > 27 {
			displayName = displayName[:24] + "..."
		}
		fmt.Printf("  │ %-27s │ %8d │ ", displayName, count)
		sevC.Printf("%-8s", strings.ToUpper(sev))
		fmt.Println(" │")
	}
	titleC.Println("  └─────────────────────────────┴──────────┴──────────┘")

	if len(ipCount) > 0 {
		fmt.Println()
		titleC.Println("  EN COK GORULEN IP ADRESLERI:")
		count := 0
		for ip, c := range ipCount {
			if count >= 5 {
				break
			}
			infoC.Printf("    %-18s : %d\n", ip, c)
			count++
		}
	}

	waitEnter(reader)
}

func menuTail(reader *bufio.Reader, cfg *Config) {
	clearScreen()
	titleC.Println("\n═══ GERCEK ZAMANLI IZLEME ═══\n")

	path := readInput(reader, "Izlenecek dosya yolu: ")
	if path == "" {
		return
	}

	if _, err := os.Stat(path); err != nil {
		errorC.Printf("Dosya bulunamadi: %v\n", err)
		waitEnter(reader)
		return
	}

	successC.Println("\nIzleme baslatildi! Durdurmak icin Ctrl+C basiniz...\n")

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	go func() {
		<-sigCh
		cancel()
	}()

	tailFile(ctx, path, cfg)

	signal.Stop(sigCh)
	fmt.Println()
	successC.Println("Izleme durduruldu.")
	waitEnter(reader)
}

func menuRules(reader *bufio.Reader, cfg *Config) {
	clearScreen()
	titleC.Println("\n═══ TANIMLI KURALLAR ═══\n")

	titleC.Println("  ┌────┬─────────────────────────────┬────────────┬────────┐")
	titleC.Println("  │ #  │ Kural Adi                   │ Severity   │ Durum  │")
	titleC.Println("  ├────┼─────────────────────────────┼────────────┼────────┤")

	for i, r := range cfg.Rules {
		status := "AKTIF"
		statusC := successC
		if !r.Enabled {
			status = "PASIF"
			statusC = errorC
		}
		sevC := getSevColor(r.Severity)

		displayName := r.Name
		if len(displayName) > 27 {
			displayName = displayName[:24] + "..."
		}

		fmt.Printf("  │ %-2d │ %-27s │ ", i+1, displayName)
		sevC.Printf("%-10s", strings.ToUpper(r.Severity))
		fmt.Print(" │ ")
		statusC.Printf("%-6s", status)
		fmt.Println(" │")
	}

	titleC.Println("  └────┴─────────────────────────────┴────────────┴────────┘")

	fmt.Println()
	infoC.Println("  Kurallar configs/rules.yaml dosyasindan yuklenir.")
	infoC.Println("  Kurallari duzenlemek icin bu dosyayi editleyiniz.")

	waitEnter(reader)
}

func menuReport(reader *bufio.Reader, cfg *Config, matches []Match) {
	clearScreen()
	titleC.Println("\n═══ CSV RAPOR OLUSTUR ═══\n")

	if len(matches) == 0 {
		warnC.Println("  Henuz bir analiz yapilmadi!")
		infoC.Println("  Lutfen once '1. Log Dosyasi Analiz Et' ile analiz yapin.")
		waitEnter(reader)
		return
	}

	infoC.Printf("  %d adet eslesen kayit bulundu.\n\n", len(matches))
	infoC.Println("  1. Raporu kaydet")
	infoC.Println("  2. Geri")
	fmt.Println()

	choice := readInput(reader, "Seciminiz: ")
	if choice != "1" {
		return
	}

	path, err := saveCSV(matches, cfg.Settings.OutputPath)
	if err != nil {
		errorC.Printf("  Hata: %v\n", err)
	} else {
		successC.Printf("  Rapor olusturuldu: %s\n", path)
	}

	waitEnter(reader)
}

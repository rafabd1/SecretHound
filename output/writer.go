package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// SecretFindingData é uma struct para armazenar os detalhes de um único segredo encontrado.
// Usada quando a saída é agrupada por fonte.
type SecretFindingData struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	// Certainty   string `json:"certainty,omitempty"` // Exemplo, descomentar se tiver
	// Severity    string `json:"severity,omitempty"`  // Exemplo, descomentar se tiver
	SourceURL   string `json:"source_url"` // URL/caminho do arquivo específico onde o segredo foi encontrado (diferente da fonte principal de agrupamento)
	Line        int    `json:"line_number,omitempty"`
	Context     string `json:"context,omitempty"`
	Description string `json:"description,omitempty"`
}

type Writer struct {
	file                *os.File
	mu                  sync.Mutex
	format              string // "json", "txt", "csv"
	rawMode             bool
	isGroupedBySource   bool   // Novo: Flag para indicar modo de agrupamento
	groupedFindings     map[string][]SecretFindingData // Novo: Mapa para armazenar segredos agrupados
	isFirstRawJsonWrite  bool   // para formatação de JSON raw
	count               int
}

/* 
   Creates a new writer instance for outputting secrets.
   Accepts rawMode and groupedMode flags.
*/
func NewWriter(outputPath string, rawMode bool, groupedMode bool) (*Writer, error) {
	dir := filepath.Dir(outputPath)
	if outputPath != "" && dir != "." && dir != outputPath { // Só cria o diretório se outputPath for um caminho, não stdout nem arquivo no diretório atual.
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %v", err)
		}
	}

	ext := strings.ToLower(filepath.Ext(outputPath))
	format := "txt"
	if ext == ".json" {
		format = "json"
	} else if ext == ".csv" {
		format = "csv"
	}

	var f *os.File
	var err error
	if outputPath != "" {
		f, err = os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %v", err)
		}
	} else {
		f = os.Stdout // Usar stdout se outputPath for vazio
	}

	w := &Writer{
		file:                f,
		format:              format,
		rawMode:             rawMode,
		isGroupedBySource:   groupedMode,
		isFirstRawJsonWrite:  true,
		count:               0,
	}

	if groupedMode {
		w.groupedFindings = make(map[string][]SecretFindingData)
	} else {
		// Lógica de escrita de header para modo não agrupado (original)
		if format == "json" && !rawMode {
			_, err = w.file.WriteString("[\n")
			if err != nil {
				if outputPath != "" { w.file.Close() }
				return nil, fmt.Errorf("failed to write JSON header: %v", err)
			}
		} else if format == "csv" && !rawMode {
			_, err = w.file.WriteString("Type,Value,URL,Context\n")
			if err != nil {
				if outputPath != "" { w.file.Close() }
				return nil, fmt.Errorf("failed to write CSV header: %v", err)
			}
		}
	}

	return w, nil
}

// WriteSecret registra um segredo encontrado.
// Se isGroupedBySource for true, armazena para escrita posterior em Close().
// Caso contrário, escreve imediatamente.
// O parâmetro `sourceForGrouping` é a URL/caminho do arquivo fonte principal.
// Os parâmetros secretType, value, specificSourceURL, context, description, line referem-se ao segredo individual.
func (w *Writer) WriteSecret(sourceForGrouping, secretType, value, specificSourceURL, context, description string, line int) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.count++ // Incrementa a contagem total de segredos encontrados, independentemente do modo

	if w.isGroupedBySource {
		finding := SecretFindingData{
			Type:        secretType,
			Value:       value,
			SourceURL:   specificSourceURL, // URL específica onde o segredo foi encontrado
			Line:        line,
			Context:     context,
			Description: description,
		}
		w.groupedFindings[sourceForGrouping] = append(w.groupedFindings[sourceForGrouping], finding)
		return nil // Nenhum erro de escrita imediata
	}

	// Lógica de escrita imediata (original, para modo não agrupado)
	var output string
	var err error

	if w.rawMode {
		if w.format == "json" {
			prefix := ""
			if w.isFirstRawJsonWrite {
				prefix = "["
				w.isFirstRawJsonWrite = false
			} else {
				prefix = ","
			}
			jsonValueBytes, jsonErr := json.Marshal(value)
			if jsonErr != nil {
				return fmt.Errorf("failed to marshal raw JSON value: %v", jsonErr)
			}
			output = prefix + string(jsonValueBytes)
		} else {
			output = value + "\n"
		}
		// Verifica se w.file é stdout ou um arquivo real antes de escrever
		if w.file == os.Stdout {
			fmt.Print(output) // Para stdout, usar fmt.Print ou fmt.Println
		} else {
			_, err = w.file.WriteString(output)
		}

	} else {
		if w.format == "json" {
			secret := map[string]interface{}{
				"type":        secretType,
				"value":       value,
				"url":         specificSourceURL,
				"context":     context,
				"line_number": line,        // Adicionado line_number
				"description": description, // Adicionada description
			}
			jsonBytes, jsonErr := json.MarshalIndent(secret, "  ", "  ")
			if jsonErr != nil {
				return fmt.Errorf("failed to marshal standard JSON: %v", jsonErr)
			}
			if w.count > 1 && w.file != os.Stdout { // Só adiciona vírgula se não for o primeiro e não for stdout (stdout já tem o [ inicial)
				output = ",\n  " + string(jsonBytes)
			} else {
				output = "  " + string(jsonBytes) // Para o primeiro item ou se for stdout sem o [ inicial já escrito por NewWriter
			}
			// Verifica se w.file é stdout ou um arquivo real antes de escrever
			if w.file == os.Stdout {
				// Se for stdout e JSON, a formatação de array ([...]) deve ser tratada em Close() ou antes/depois do loop de escrita
				// Por agora, vamos assumir que o cabeçalho [ foi escrito se necessário, ou será em Close().
				// Esta lógica de escrita imediata para JSON em stdout é complexa de alinhar com o modo agrupado.
				// Para simplificar, o modo agrupado não escreverá em stdout até o final.
				// Esta parte da escrita imediata precisa ser consistente com a escrita de header em NewWriter.
				if w.count == 1 { // Se for o primeiro, não precisa de vírgula.
					fmt.Print(output) 
				} else {
					fmt.Print(",\n" + output) // Adiciona vírgula e nova linha para itens subsequentes
				}
			} else {
				_, err = w.file.WriteString(output)
			}

		} else if w.format == "csv" {
			output = fmt.Sprintf("%s,\"%s\"%s,\"%s\",\"%s\",%d\n", // Incluindo description e line
				secretType, escapeCsv(value), escapeCsv(specificSourceURL), escapeCsv(context), escapeCsv(description), line)
			// Verifica se w.file é stdout ou um arquivo real antes de escrever
			if w.file == os.Stdout {
				fmt.Print(output)
			} else {
				_, err = w.file.WriteString(output)
			}

		} else { // txt format
			output = fmt.Sprintf("[%s] %s\nURL: %s\nContext: %s\nDescription: %s\nLine: %d\n\n",
				secretType, value, specificSourceURL, context, description, line)
			// Verifica se w.file é stdout ou um arquivo real antes de escrever
			if w.file == os.Stdout {
				fmt.Print(output)
			} else {
				_, err = w.file.WriteString(output)
			}
		}
	}

	return err
}

/* 
   Finalizes and closes the output file. If isGroupedBySource is true,
   this is where the grouped data is actually written.
*/
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Se estiver no modo agrupado, escreve todos os achados agrupados agora.
	if w.isGroupedBySource && w.groupedFindings != nil && len(w.groupedFindings) > 0 {
		if w.format == "json" {
			var jsonBytes []byte
			var err error
			if w.rawMode {
				rawGroupedFindings := make(map[string][]string)
				for source, findings := range w.groupedFindings {
					values := make([]string, len(findings))
					for i, finding := range findings {
						values[i] = finding.Value
					}
					rawGroupedFindings[source] = values
				}
				jsonBytes, err = json.MarshalIndent(rawGroupedFindings, "", "  ")
			} else {
				jsonBytes, err = json.MarshalIndent(w.groupedFindings, "", "  ")
			}

			if err != nil {
				// Mesmo se houver erro no Marshal, tenta fechar o arquivo se ele existir e não for stdout.
				if w.file != nil && w.file != os.Stdout {
					w.file.Close()
				}
				w.file = nil // Marca como nil para evitar fechamento duplo
				return fmt.Errorf("failed to marshal grouped JSON data: %v", err)
			}

			if w.file == os.Stdout {
				fmt.Println(string(jsonBytes)) // Imprime para stdout
			} else if w.file != nil {
				_, err = w.file.Write(jsonBytes)
				if err != nil {
					w.file.Close() // Tenta fechar em caso de erro de escrita
					w.file = nil
					return fmt.Errorf("failed to write grouped JSON data to file: %v", err)
				}
				if len(jsonBytes) > 2 { // Adiciona nova linha se houver conteúdo
					 w.file.WriteString("\n")
				}
			}
		} else if w.format == "txt" { // Formato de texto agrupado
			var sb strings.Builder
			// Ordenar as chaves do mapa para saída determinística
			keys := make([]string, 0, len(w.groupedFindings))
			for k := range w.groupedFindings {
				keys = append(keys, k)
			}
			// sort.Strings(keys) // Descomentar se a ordem das fontes for importante

			for _, source := range keys {
				findings := w.groupedFindings[source]
				sb.WriteString(source + ":\n")
				for _, finding := range findings {
					sb.WriteString(fmt.Sprintf("\t[%s] %s\n", finding.Type, finding.Value))
					sb.WriteString(fmt.Sprintf("\tURL: %s\n", finding.SourceURL))
					if finding.Line > 0 {
						sb.WriteString(fmt.Sprintf("\tLine: %d\n", finding.Line))
					}
					sb.WriteString(fmt.Sprintf("\tContext: %s\n", finding.Context))
					if finding.Description != "" {
						sb.WriteString(fmt.Sprintf("\tDescription: %s\n", finding.Description))
					}
					sb.WriteString("\n") 
				}
			}
			if w.file == os.Stdout {
				fmt.Print(sb.String())
			} else if w.file != nil {
				_, err := w.file.WriteString(sb.String())
				if err != nil {
					w.file.Close()
					w.file = nil
					return fmt.Errorf("failed to write grouped text data to file: %v", err)
				}
			}
		} else if w.format == "csv" {
			// CSV agrupado não implementado conforme solicitado.
		}
	} else if w.format == "json" && !w.isGroupedBySource { // Lógica original para JSON não agrupado
		var finalWriteErr error
		if w.rawMode {
			if !w.isFirstRawJsonWrite { 
				if w.file == os.Stdout {
					fmt.Print("]")
				} else if w.file != nil {
					_, finalWriteErr = w.file.WriteString("]")
				}
			} else { 
				if w.file == os.Stdout {
					fmt.Print("[]")
				} else if w.file != nil {
					_, finalWriteErr = w.file.WriteString("[]")
				}
			}
		} else { // JSON padrão não raw, não agrupado
			if w.file == os.Stdout {
				// Em NewWriter, para stdout, não escrevemos o '[' inicial para JSON não agrupado e não raw.
				// A escrita de cada item em WriteSecret já lida com a vírgula.
				// Então, aqui só precisamos fechar se algo foi escrito.
				if w.count > 0 { // Se houve itens, o último não tem vírgula, então só nova linha e fechar.
					fmt.Print("\n]")
				} else {
					fmt.Print("[]") // Se nenhum item, imprime array vazio.
				}
			} else if w.file != nil {
				_, finalWriteErr = w.file.WriteString("\n]")
			}
		}
		if finalWriteErr != nil && w.file != nil && w.file != os.Stdout {
			w.file.Close()
			w.file = nil
			return fmt.Errorf("failed to finalize non-grouped JSON output: %v", finalWriteErr)
		}
	}

	// Fecha o arquivo se ele não for stdout e ainda estiver aberto (e não foi fechado por erro anterior)
	if w.file != nil && w.file != os.Stdout {
		closeErr := w.file.Close()
		w.file = nil 
		return closeErr 
	}

	return nil 
}

func escapeCsv(field string) string {
	return strings.ReplaceAll(field, "\"", "\"\"")
}

func (w *Writer) GetCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}

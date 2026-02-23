# go-ast-processor-cli

## Инструмент для построения дерева вызовов функций (консольная версия)

### Как пользоваться консольной утилитой?

![Ввод команд-1](local/img/cli_1.png)
![Ввод команд-2](local/img/cli_2.png)


### Развитие функционала (Микросервисная архитектура)


![Архитектура микросервисов](local/img/architecture.png)

Архитектура отображения графов вызовов уязвимых функций
Микросервисы:
- sast-report-viewer
- call-graph-scheduler
- go-callgraph-processor
- call-graph-viewer
- vulnerability-cleaner
- ml-predictor
- API-шлюз

Топики Kafka:
- callgraph.required
- callgraph.completed
- go.callgraph.cleanup
- vulnerability.cleanup

1. Сначала проводим статический анализ в CI/CD, получаем отчет статического анализатора, например, semgrep, в формате JSON.
2. Вызываем ручку POST сервиса call-graph-scheduler: передаем отчет и ссылку на Gitlab.
3. Сервис call-graph-scheduler клонируют репозиторий в локальную директорию.
   SAST-отчет отправляет с помощью ручки POST сервиса sast-report-viewer, сервис sast-report-viewer десериализует отчет и сохраняет содержимое в БД.
   В ответ  sast-report-viewer возвращает список *vulnerabilityId* (который далее используется для поиска графа вызовов в качестве метки) и информацию о местоположении каждой уязвимости.
   Если vulnerabilityId был получен, то исходный код сервис call-graph-scheduler сохраняет в S3-хранилище. Здесь используется жесткая связность, поскольку в случае если отчет некорректен, то дальнейшее построение графа не имеет смысла.
4. Сервис call-graph-scheduler отправляет сообщение Kafka в топик callgraph.required с метаданными о сохраненных ресурсах в S3-хранилище + списка информации об уязвимостях.
   Информация об уязвимостях в сообщении кафки представлено следующим образом:

```json
{
  "vulnerabilityId": "7ba5ebfe-8455-4baf-b718-7fce32bdd86e",
  "filePath": "internal/pathtraversal/dfs.go",
  "functionName": "FindPath",
  "lineNumber": 28
}
```

5. Сервис go-callgraph-processor вычитывает сообщение из Кафки из топика  callgraph.required, начинает обработку в асинхронном методе.

6. В этом методе go-callgraph-processor выгружает исходный код и JSON-отчет.
   Вычитываем сообщение из топика  callgraph.required и получаем информацию о местоположении уязвимости,
   по этой информации строим граф вызовов для уязвимых функций и сохраняет граф вызовов в Redis-хранилище с большим TTL (например, 7 дней).

   Он в другом топике - в callgraph.completed отправляет сообщение о том, что построение прошло успешно и информацию о ключах в Redis, которым соответствуют графы вызовов, или наоборот, если неуспешно.
   Сервис call-graph-viewer вычитывает сообщение из Кафки, по каждому каждого ключу Redis сервис call-graph-viewer получает граф вызовов, который сохраняется в графовую БД.
   Для экономии ресурсов можно использовать схему Postgres.
   Примерная схема Postgres:
```sql
CREATE TABLE callgraph_nodes (
    vulnerability_id UUID NOT NULL,
    node_id SERIAL PRIMARY KEY,
    function_name TEXT NOT NULL,
    file_path TEXT,
    function_content TEXT,
    PRIMARY KEY(vulnerability_id, node_id)
);

CREATE TABLE callgraph_edges (
    vulnerability_id UUID NOT NULL,
    from_node_id INTEGER REFERENCES callgraph_nodes(node_id),
    to_node_id INTEGER REFERENCES callgraph_nodes(node_id),
    PRIMARY KEY (vulnerability_id, from_node_id, to_node_id)
);

CREATE INDEX ON callgraph_nodes(vulnerability_id);
CREATE INDEX ON callgraph_edges(vulnerability_id);
```
Добавить граф вызовов в сообщение в топике callgraph.completed нельзя, так как если уязвимостей много, сообщение кафки будет большим.
Если по какой-то причине сохранение графа для vulnerabilityId не было успешным, то сообщение из топика callgraph.completed коммитим, но отправляем новое с теми vulnerabilityId, которые не были сохранены.
Иначе - просто коммитим сообщение в топике callgraph.completed, затем отправляем сообщение в Кафку в топик go.callgraph.cleanup.
Функционал сервиса call-graph-viewer следующий:

- GET-запрос: по vulnerabilityId вернуть граф вызовов.

7. Сервис go-callgraph-processor вычитывает сообщение из топика go.callgraph.cleanup и осуществляет удаление графа из своей БД.
   8По крон-выражению vulnerability-cleaner вызывает ручку GET сервиса sast-report-viewer и получает список vulnerabilityId всех тех уязвимостей, отчеты которого долго хранятся и требует очистки.
   Сервис vulnerability-cleaner отправляет сообщение в топик vulnerability.cleanup с информацией о устаревших vulnerabilityId. Сервисы call-graph-viewer и sast-report-viewer удаляют устаревшие данные из своих БД.

8. Сервис API-шлюз ответственен за авторизацию публичных API и вызов сервисов sast-report-viewer и call-graph-viewer.

Если требуется поддержка других языков программирования, то добавляем сервис processor (например, для java - java-ast-processor).

9. Информацию с go-callgraph-processor можно использовать как основу для ml-predictor. Сервис ml-predictor будет использовать модель mahdin70/GraphCodeBERT-VulnCWE, которая определяет вероятность уязвимости по построенному графу вызовов.
   С помощью SNAP ((SHapley Additive exPlanations) — алгоритм из теории игр, который разбивает предсказание модели на вклады каждого входного элемента) можно подсветить уязвимые участки кода.

### Идеи для развития

Потенциальный функционал инструмента:

- [ ] Построение дерева вызовов для одной функции
- [ ] Можно выявить связь между двумя функциями, где, например, одна функция вызывает другую. Для этого нужно просто построить два дерева и обойти каждое из них.
- [ ] Предсказание о конкретной реализации интерфейса функции по дереву вызова, используя информацию о типе.
- [ ] Поиск инициализации переменной

### Про VTA

Алгоритм VTA строит глобальный граф распространения типов, который моделирует потоки данных в программе.
Он передает типы и функциональные литералы по этому графу, чтобы определить, какие типы могут оказаться в каждой переменной. Этот подход позволяет более точно определять возможные получатели динамических вызовов методов.


# code-map — 用户指南

一个以 MCP 服务器形式提供的代码库结构映射工具。你把它指向一个项目，它就用 `tree-sitter` / AST 读取代码，并构建出代码组织方式的各种地图。与它配套的审计工具一样，它**从不运行你的代码**。

## 它是什么

`code-map` 是一个只读的静态映射工具。它将源代码解析成语法树，并生成结构化的地图：什么导入了什么、定义了哪些符号、运行时入口点在哪里、存在哪些数据契约以及它们如何漂移、谁在写入文件 / 数据库 / 环境变量、风险热点在哪里、以及一次重构的自然边界落在何处。它用于*理解*一个代码库，而不是查找 bug（查 bug 请使用 `forensic-audit` 服务器）。

支持的语言：**Python、Go、Java、JavaScript、TypeScript**。

## 它能给你什么

它生成 **8 种地图类型**，其中 **6 种开箱即用**、无需任何配置：

- **structural**——导入与符号。准确。
- **data_contract**——dataclass / struct、它们的形状（shape）、漂移检测，以及写入者 / 读取者（writers / readers）。
- **hotspot**——每个文件的风险分数。
- **conflict**——schema 冲突。
- **authority**——谁在写入文件 / 数据库 / 环境变量。无需配置即可自动浮现写入点。
- **runtime**——入口点（`__main__` / async）。无需配置即可自动浮现。

第 7 种地图 **refactor_boundary** 是**由 seed 驱动**的：它需要一个重构目标才能工作。（第 8 种 `findings` 是从其他地图派生而来的。）

输出**以摘要为先**：默认你得到每种地图类型的计数，外加每张地图的头部条目。用 `map='structural'` 请求某一张完整的地图，或用 `view='full'` 请求所有地图。

输出是**确定性的**——语义 diff 会忽略时间戳，因此相同的代码会产出相同的地图。结果会**缓存在磁盘上**，位于 `<project>/.cortex/` 之下，从而让重复运行很廉价。

## 何时使用

- 当你来到一个不熟悉的代码库、需要快速理解其架构时。
- 用于查找什么导入了什么、或什么依赖什么。
- 用于定位运行时入口点或风险热点。
- 用于评估一次重构的范围（并在有 seed 时找出它的边界）。
- 用于查看谁在写入文件 / 数据库 / 环境变量——authority 地图会自动浮现写入点。

它**不是**代码质量审计工具——对于 bug、被吞掉的异常和安全异味，请使用 `forensic-audit` 服务器。

## 如何安装与使用

目前这是一个**本地可编辑安装（editable install）**（尚未发布到 PyPI）。它在你安装它的那台机器上可用；发布到 PyPI 以便在其他机器上使用的工作仍在进行中。

在 `cortex-codeintel` 仓库根目录下：

```bash
pip install -e .   # 在 cortex-codeintel 仓库中执行
claude mcp add code-map -s user -- <abs-path-to-venv-python> -m cortex_mcp.map_server
```

请将 `<abs-path-to-venv-python>` 替换为你虚拟环境中 Python 解释器的绝对路径，例如在 Windows 上：

```
C:\Users\You\path\to\cortex-codeintel\.venv\Scripts\python.exe
```

添加之后，该服务器提供一套**后台任务 + 轮询**的 API。典型流程如下：

1. `start_code_map(path)` → 返回一个 `job_id` 和 `resolved_path`。将 `path` 留空可从当前目录向上查找以自动检测项目根目录。
2. `get_code_map_status(job_id)` → 轮询直到 `status == "done"`。
3. `get_code_map_results(job_id)` → 精简摘要（每张地图的计数 + 头部条目）。请先读这一份。
4. 深入查看：用 `get_code_map_results(job_id, map='structural')` 查看某一张完整地图，或用 `view='full'` 查看所有地图（两者均通过 `page=` 分页）。

若要在不启动新任务的情况下重新读取早先会话中构建的地图，请使用 `load_code_map_by_path(path)`。

省略 `path` 时，项目根目录会被自动检测。

## 优点

- **7 张地图中有 6 张零配置即可工作。**
- **功能丰富的 `data_contract` 地图**，带漂移检测。
- **准确的 structural 地图。**
- **5 种语言**（Python、Go、Java、JS、TS）。
- **确定性**——语义 diff 忽略时间戳。
- **摘要契合你的上下文预算。**

## 缺点与局限

诚实地说明不足之处：

- **`refactor_boundary` 需要一个 seed**（重构目标）。没有它就不会产出边界。
- **`authority` 地图在 Python 上的发现并不完整。** 它能捕获 `open('w')`、`write_text` 和 `json.dump`，但**捕获不到** `os.fdopen` + `os.replace` 这种原子写入惯用法，也捕获不到数据库 / 环境变量的写入。（Go / Java 适配器确实能捕获数据库写入。）
- **某些入口点不会被浮现。** 仅通过打包的 `console_scripts` 暴露（文件内没有 `__main__`）的入口点不会被检测到。
- **单张地图的完整视图可能很大**——在中等规模的项目上可达约 32k 字符。它是分页的，所以请逐页翻看，而不要期望一次性拿到全部。

## 调优

- 大多数地图**无需配置**——7 张中有 6 张开箱即用。
- 唯一的例外是 **`refactor_boundary`**：把重构目标作为它的 seed 提供，让它知道要计算哪条边界。
- **先用摘要**，然后用 `map='<type>'`（例如 `map='structural'`）深入查看某一张地图，或用 `view='full'` 获取全部。两种视图都通过 `page=` 分页。
- 结果会**缓存在磁盘上**，位于 `<project>/.cortex/` 之下；`load_code_map_by_path(path)` 可在不重新构建的情况下重新读取它们。

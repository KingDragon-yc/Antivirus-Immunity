# Antivirus-Immunity

> **"A kind of Antivirus inspired by immune system."**

## 📖 项目愿景 (Vision)

本项目旨在构建一个基于**人工免疫系统 (AIS)** 理论的端点安全防护软件。与依赖特征库的传统杀毒软件不同，Antivirus-Immunity 侧重于：
- **自我识别 (Self/Non-Self Discrimination)**: 通过建立系统“正常态”的基线，识别入侵者。
- **行为免疫 (Behavioral Immunity)**: 基于行为模式而非静态特征来检测威胁。
- **自适应性 (Adaptability)**: 能够对未知的攻击手段做出反应。

## 🏗 架构设计 (Architecture)

系统由三个核心部分组成，模拟生物免疫回路：

### 1. 感知层 (Sensors / Innate Immunity)
*对应生物学：皮肤、巨噬细胞*
- **功能**: 负责实时监控系统状态。
- **技术**: 
    - Windows ETW (Event Tracing for Windows)
    - File System Minifilter (文件变动监控)
    - Process Callbacks (进程创建/销毁监控)

### 2. 决策层 (Core / Adaptive Immunity)
*对应生物学：T细胞、B细胞、淋巴结*
- **功能**: 分析感知层传来的数据，判断是否为威胁。
- **模块**:
    - **Negative Selection (负向选择)**: 过滤掉已知的“自身”进程（白名单）。
    - **Danger Theory (危险理论)**: 监测系统压力的信号（如CPU突然飙升、大量文件被重命名）。
    - **Memory Cell (记忆细胞)**: 缓存已分析过的进程特征。

### 3. 响应层 (Effectors)
*对应生物学：抗体中和、细胞吞噬*
- **功能**: 对确认为威胁的目标采取行动。
- **动作**:
    - **Quarantine (隔离)**: 移动文件到隔离区。
    - **Terminate (杀伤)**: 结束恶意进程。
    - **Alert (炎症反应)**: 通知用户。

## 🛠 技术栈 (Tech Stack)

- **开发语言**: Rust (主要), Python (辅助分析)
- **操作系统**: Windows (首选目标平台)
- **关键库**: 
    - `windows-rs` (WinAPI 交互)
    - `ferris-gram` (ETW 封装，待定)

## 🚀 路线图 (Roadmap)

### Phase 1: 骨架构建 (Skeleton)
- [ ] 搭建 Rust 项目结构
- [ ] 实现基础的进程监控 (Process Monitor)
- [ ] 实现简单的“白名单”机制

### Phase 2: 免疫机制 (Immunity)
- [ ] 引入 ETW 监控文件操作
- [ ] 实现基础的行为分析 (例如：检测勒索软件诱饵文件的修改)

### Phase 3: 进化 (Evolution)
- [ ] 引入简单的机器学习模型进行异常检测
- [ ] 构建 Web 控制台

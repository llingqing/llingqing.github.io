---
title: 队列（Queue）
tags: [数据结构, 考研, 队列]
published: 2026-07-05
category: 数据结构
draft: false
---
:::warning
含AI生成内容
:::

# 队列（Queue）

## 定义

**队列**（Queue）是只允许在**一端插入**、**另一端删除**的线性表。插入的一端称为**队尾**（rear），删除的一端称为**队头**（front）。

核心特性：**先进先出**（First In First Out, FIFO）。

```
出队 ← [e₁][e₂][e₃][e₄] ← 入队
       队头            队尾
```

### 基本操作

| 操作 | 说明 | 时间复杂度 |
|------|------|-----------|
| InitQueue(&Q) | 初始化空队列 | O(1) |
| EnQueue(&Q, e) | 入队（队尾插入） | O(1) |
| DeQueue(&Q, &e) | 出队（队头删除） | O(1) |
| GetHead(Q, &e) | 读队头元素 | O(1) |
| QueueEmpty(Q) | 判空 | O(1) |

### 队列的典型应用

| 应用场景 | 说明 |
|---------|------|
| 层次遍历（BFS） | 树/图的 BFS 用队列逐层处理 |
| CPU 资源分配 | 多进程按 FIFO 排队（时间片轮转调度） |
| 打印缓冲区 | 多个打印请求排队等待 |
| 主机与外设速度匹配 | 缓冲区（队列）协调速度差异 |

---

## 循环队列

### 存储结构

```c
#define MaxSize 10
typedef struct {
    int data[MaxSize];
    int front, rear;   // front 指向队头元素，rear 指向队尾下一个位置
} SqQueue;
```

指针移动公式（取模实现"循环"）：

```
front = (front + 1) % MaxSize    // 出队后 front 前进
rear  = (rear + 1) % MaxSize     // 入队后 rear 前进
```

初始状态：`front = rear = 0`。

### 判满与判空（⭐核心考点）

循环队列中 `front == rear` 可能是**队空**也可能是**队满**，必须区分。408 常考三种方案：

#### 方案一：牺牲一个存储单元（默认，最常用）

| 条件 | 表达式 |
|------|--------|
| 队空 | `front == rear` |
| 队满 | `(rear + 1) % MaxSize == front` |
| 元素个数 | `(rear - front + MaxSize) % MaxSize` |

队列最多存放 `MaxSize - 1` 个元素。

#### 方案二：增设 size 计数器

| 条件 | 表达式 |
|------|--------|
| 队空 | `size == 0` |
| 队满 | `size == MaxSize` |
| 元素个数 | `size` |

可存满 MaxSize 个元素。

#### 方案三：增设 tag 标志位

| 条件 | 表达式 |
|------|--------|
| 队空 | `front == rear && tag == 0` |
| 队满 | `front == rear && tag == 1` |

> ⚠️ **易错**：元素个数公式 `(rear - front + MaxSize) % MaxSize` 不要忘记加 MaxSize 再取模——直接 `rear - front` 可能得到负数。方案一最常搭配此公式使用。

### 核心操作

**入队**：
```c
bool EnQueue(SqQueue *Q, int x) {
    if ((Q->rear + 1) % MaxSize == Q->front)
        return false;                    // 队满
    Q->data[Q->rear] = x;
    Q->rear = (Q->rear + 1) % MaxSize;
    return true;
}
```

**出队**：
```c
bool DeQueue(SqQueue *Q, int *x) {
    if (Q->front == Q->rear)
        return false;                    // 队空
    *x = Q->data[Q->front];
    Q->front = (Q->front + 1) % MaxSize;
    return true;
}
```

### 复杂度分析

| 操作 | 时间复杂度 |
|------|-----------|
| 入队/出队/取队头 | O(1) |
| 判空/判满 | O(1) |
| 空间复杂度 | O(1) 辅助空间 |

---

## 链式队列

### 存储结构

```c
// 链式队列结点
typedef struct LinkNode {
    int data;
    struct LinkNode *next;
} LinkNode;

// 链式队列（带头结点）
typedef struct {
    LinkNode *front;   // 队头指针，指向头结点
    LinkNode *rear;    // 队尾指针，指向最后一个元素
} LinkQueue;
```

队列状态：
```
空队列:   front -> [头结点] <- rear
                     next=NULL

非空队列: front -> [头结点] -> [a₁] -> [a₂] -> [a₃] <- rear
                                                  next=NULL
```

**判空条件**：`Q.front == Q.rear`（都指向头结点）。

### 核心操作

**入队**：
```c
bool EnQueue(LinkQueue *Q, int x) {
    LinkNode *s = (LinkNode *)malloc(sizeof(LinkNode));
    if (s == NULL) return false;
    s->data = x;
    s->next = NULL;
    Q->rear->next = s;   // 新结点插入到 rear 之后
    Q->rear = s;         // 修改队尾指针
    return true;
}
```

**出队（⚠️ 易错：只剩一个元素时需同时修改 rear）**：
```c
bool DeQueue(LinkQueue *Q, int *x) {
    if (Q->front == Q->rear) return false;   // 队空
    LinkNode *p = Q->front->next;
    *x = p->data;
    Q->front->next = p->next;
    if (Q->rear == p)              // 若原队列只有一个结点
        Q->rear = Q->front;        // rear 指回头结点
    free(p);
    return true;
}
```

> ⚠️ **易错**：出队时如果被删结点是队列中唯一元素（p 既是队头也是队尾），必须将 `rear` 重新指向头结点，否则 `rear` 成为野指针。

### 链式队列 vs 循环队列

| 对比项 | 循环队列 | 链式队列 |
|--------|---------|---------|
| 存储空间 | 静态分配，固定大小 | 动态分配，按需增长 |
| 溢出 | 可能溢出 | 不会溢出 |
| 实现复杂度 | 简单 | 稍复杂 |
| 缓存性能 | 好（连续存储） | 差（离散存储） |

---

## 双端队列

### 定义

双端队列（Deque）是两端都可以进行插入和删除的线性表。

```
  前端 front                      后端 rear
    ↕                               ↕
 ┌──────┬──────┬──────┬──────┬──────┐
 │  a₁  │  a₂  │  a₃  │  a₄  │  a₅  │
 └──────┴──────┴──────┴──────┴──────┘
  可插入/删除                    可插入/删除
```

- 栈和队列都是双端队列的特例（限制操作方式后退化而成）

### 受限双端队列

| 类型 | 前端 | 后端 |
|------|------|------|
| **输入受限** | 只能删除 | 可插入、可删除 |
| **输出受限** | 可插入、可删除 | 只能删除 |

**包含关系**：
> 栈的合法序列 ⊂ 受限双端队列的合法序列 ⊂ 一般双端队列的合法序列

> ⚠️ **易错**：输入受限是限制"输入"只能从一端进行，两端都能输出；输出受限是限制"输出"只能从一端进行，两端都能输入。

---

## 考研高频考点

- ⭐ 循环队列判满判空三种方案的区别与表达式
- ⭐ 元素个数公式 `(rear - front + MaxSize) % MaxSize`
- ⭐ 链式队列判空条件 `Q.front == Q.rear`
- ⭐ 出队时只剩一个元素需同时修改 rear 指针
- ⭐ 双端队列输出序列判断（⾼频选择题）
- ⭐ 输入受限 vs 输出受限双端队列的序列生成能力辨析
- 队列在层序遍历（BFS）中的应用
- 链式队列 vs 循环队列优缺点对比


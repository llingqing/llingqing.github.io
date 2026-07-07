---
title: 交换排序
tags: [数据结构, 排序, concept, 交换排序]
published: 2026-07-07
updated: 2026-07-07
category: 数据结构
slug: sorting-exchange
draft: false
---

# 交换排序

交换类排序的核心操作：比较两个元素，若逆序则交换。代表算法有**冒泡排序**和**快速排序**。

## 冒泡排序

### 核心思想

- **相邻比较**：每次比较相邻的两个元素，如果逆序则交换
- **逐趟冒泡**：每一趟都将当前未排序部分的最大元素"冒泡"到末尾
- **提前终止**：若某一趟没有发生任何交换，说明序列已有序，可直接结束

### 代码实现（带提前终止优化）

```c
void BubbleSort(int a[], int n) {
    for (int i = 0; i < n - 1; i++) {
        bool swapped = false;
        for (int j = 0; j < n - 1 - i; j++) {
            if (a[j] > a[j + 1]) {
                int tmp = a[j];
                a[j] = a[j + 1];
                a[j + 1] = tmp;
                swapped = true;
            }
        }
        if (!swapped) break;   // 本趟无交换，提前终止
    }
}
```

### 复杂度

| 情况 | 时间 | 说明 |
|------|------|------|
| 最好 | O(n) | 已有序，一趟遍历无交换即终止 |
| 最坏 | O(n²) | 逆序 |
| 平均 | O(n²) | — |
| 空间 | O(1) | 常数级辅助变量 |
| 稳定 | **稳定** | 相等元素不交换 |

> ⚠️ **易错**：冒泡排序的**最好情况是 O(n)**，前提是代码中有提前终止优化。

## 快速排序

### 核心思想

快排是排序章节**考频最高**的算法。核心是**分治法**：

- **分区**：选一个元素作为**基准（pivot）**，将序列划分为两部分——左边 ≤ pivot，右边 ≥ pivot
- **递归**：对左右子序列分别递归执行快速排序
- **合并**：无需合并，分区完成后序列自然有序

### Partition 过程（⭐ 必考手写）

以第一个元素为 pivot，双指针从两端向中间扫描：

```c
int Partition(int A[], int low, int high) {
    int pivot = A[low];
    while (low < high) {
        while (low < high && A[high] >= pivot) high--;
        A[low] = A[high];
        while (low < high && A[low] <= pivot) low++;
        A[high] = A[low];
    }
    A[low] = pivot;
    return low;
}

void QuickSort(int A[], int low, int high) {
    if (low < high) {
        int pivotPos = Partition(A, low, high);
        QuickSort(A, low, pivotPos - 1);
        QuickSort(A, pivotPos + 1, high);
    }
}
```

> ⚠️ **易错**：Partition 中 while 条件的 `>=` 和 `<=` 不能改成 `>` 和 `<`，否则与 pivot 相等时会死循环。

### 递归分析

- **最好情况**：每次 pivot 将序列等分，递归树平衡，树高 log₂n → O(n log n)
- **最坏情况**：每次 pivot 是最小/最大值，递归树退化为单链，树高 n → O(n²)

### 复杂度

| 指标 | 结果 |
|------|------|
| 最好时间 | O(n log n) |
| 平均时间 | O(n log n) |
| 最坏时间 | O(n²) |
| 空间（平均） | O(log n) |
| 空间（最坏） | O(n) |
| 稳定性 | **不稳定** |

### pivot 优化策略

1. **随机选取 pivot**：从子序列中随机选一个与 A[low] 交换
2. **三数取中法**：取 A[low]、A[mid]、A[high] 的中值作为 pivot
3. **子序列短时改用插入排序**

### 最坏情况

最坏情况发生在**序列基本有序（正序或逆序）+ 取首元素为 pivot** 时：

- 每趟只能确定一个元素的位置，需 n-1 趟
- 比较次数：n(n-1)/2 = O(n²)

> ⚠️ **易错**：快排 O(n²) 不意味着快排不好。408 常考"对任意输入数据，以下哪种最坏仍为 O(n log n)？"——答案是归并和堆排。

## 考研高频考点

### 冒泡排序
- ⭐ 每趟结果（选择题/填空题）
- ⭐ 提前终止优化的条件与最好 O(n)
- ⭐ 比较次数与交换次数计算

### 快速排序
- ⭐ ⭐ 手动模拟 Partition 过程（选择题/填空题必考）
- ⭐ 时间复杂度（最好/最坏/平均）
- ⭐ 最坏情况发生条件（有序 + 首元素 pivot）
- ⭐ 每趟至少确定一个元素的最终位置
- ⭐ 不稳定排序的反例
- **pivot 优化策略**
- **快排 vs 归并 vs 堆排的综合对比**

## 关联页面

- [排序基础概念](./sorting-basics) — 稳定性、趟的概念、算法总览
- [插入排序](./sorting-insertion) — 直接插入、希尔
- [选择排序](./sorting-selection) — 堆排序（与快排对比）
- [归并排序](./merge-sort)（与快排对比：稳定性、空间、最坏情况）

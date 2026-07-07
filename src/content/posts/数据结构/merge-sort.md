---
title: "merge-sort"
published: 2026-07-07
updated: 2026-07-07
image: api
tags: [数据结构, 排序, 归并排序]
category: 数据结构
draft: false
---
:::warning
含AI生成内容
:::
# 归并排序（二路归并）

归并排序是唯一一个**既稳定又保证 O(n log n)** 的比较排序。代价是需要 O(n) 额外空间。

## 核心思想

**分治法（Divide and Conquer）**：

1. **分解**：将数组从中间一分为二
2. **递归求解**：对左右子数组递归地进行归并排序
3. **合并**：将两个已排序子数组合并为一个有序数组

```
原始: [8,4,5,7,1,3,6,2]
分解: [8,4,5,7]        [1,3,6,2]
      [8,4] [5,7]      [1,3] [6,2]
      [8][4] [5][7]    [1][3] [6][2]
合并: [4,8] [5,7]      [1,3] [2,6]
      [4,5,7,8]        [1,2,3,6]
      [1,2,3,4,5,6,7,8]
```

## 代码实现

### Merge 函数

```c
int *B = (int *)malloc((n + 1) * sizeof(int));

void Merge(int A[], int low, int mid, int high) {
    int i, j, k;
    for (k = low; k <= high; k++)
        B[k] = A[k];
    for (i = low, j = mid + 1, k = low; i <= mid && j <= high; k++) {
        if (B[i] <= B[j])    // ⭐ <= 保证稳定性
            A[k] = B[i++];
        else
            A[k] = B[j++];
    }
    while (i <= mid)  A[k++] = B[i++];
    while (j <= high) A[k++] = B[j++];
}
```

> 比较时使用 `<=` 而非 `<`，是保证稳定性的关键——相同元素优先取左侧。

### MergeSort 递归

```c
void MergeSort(int A[], int low, int high) {
    if (low < high) {
        int mid = (low + high) / 2;
        MergeSort(A, low, mid);
        MergeSort(A, mid + 1, high);
        Merge(A, low, mid, high);
    }
}
```

## 递归分析

- 第 1 层：1 个长度为 n 的序列
- 第 2 层：2 个长度为 n/2 的序列
- 第 k 层：2^(k-1) 个长度为 n/2^(k-1) 的序列
- 共 **⌈log₂n⌉** 层（归并趟数）

每层归并操作总共 O(n)，总时间 O(n log n)。

## 复杂度

| 指标 | 值 |
|------|-----|
| 最好时间 | O(n log n) |
| 最坏时间 | O(n log n) |
| 平均时间 | O(n log n) |
| 空间 | **O(n)**（辅助数组）+ O(log n)（递归栈） |
| 稳定性 | **稳定** |
| 归并趟数 | ⌈log₂n⌉ |

> ⚠️ **易错**：归并排序的**每一趟**是对相邻有序子表两两合并。第 1 趟后每子表长 2，第 2 趟后长 4……第 k 趟后长 2^k。

## 与快速排序对比

| 对比项 | 归并排序 | 快速排序 |
|--------|----------|----------|
| 最坏时间 | O(n log n) | O(n²) |
| 平均时间 | O(n log n) | O(n log n) |
| 空间 | O(n) | O(log n) |
| 稳定性 | 稳定 | 不稳定 |
| 适用场景 | 要求稳定或最坏保证 | 内部排序平均最快 |

## 考研高频考点

- ⭐ 时间复杂度：所有情况均为 O(n log n)
- ⭐ 空间复杂度 O(n)：需与原数组等长辅助数组
- ⭐ 归并趟数 ⌈log₂n⌉
- ⭐ 是**稳定的**排序算法
- ⭐ 归并排序 vs 快速排序的对比
- Merge 操作 `<=` 保证稳定性的细节
- 每趟归并的比较次数分析

## 关联页面

- [排序基础概念](./sorting-basics.md) — 算法总览、稳定性
- [交换排序](./sorting-exchange.md) — 快速排序（归并 vs 快排对比）
- [选择排序](./sorting-selection.md) — 堆排序（归并 vs 堆排对比）
- [外部排序](./external-sort.md) — 外部排序基于归并思想
- [排序资料摘要](./sorting.md)
